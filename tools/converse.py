#!/usr/bin/env python3
#
# Copyright © 2025 Björn Victor (bjorn@victor.se)
# This is a Converse (i.e. SEND) client/server, vaguely reminiscent of Converse on LISPM.

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

# TODO:
# - test sound on Z2
# - Try to make "West Side" tabs to work, check what the highlight is doing wrong.
# - do actual sending in a separate thread, interruptible by Cancel button.
# - (optionally) save incoming msgs to disk and restore them on restart
# - FINGER/NAME client, show who of the destinations are online
# -- better still, put the destination list in a left/right margin with "present" markers, a'la Msgr
# - beep when message incoming (cf /System/Library/Sounds, https://www.qt.io/product/qt6/qml-book/ch11-multimedia-sound-effects, platform.system(), can't get it to work)
# - dock icon with counter for unseen msgs (https://doc.qt.io/qtforpython-6/overviews/qtdoc-appicon.html)
# Configuration:
# - sounds on/off
# - receiver on/off (related to if the screen is on, or idle, or ...)
# Future features: autoreply, idle detection, ignore lists...

# SEND protocol message format:
# - RFC arg: destinationUsername
# - line 1: from@host date-and-time
# - rest: message. ITS starts it with "To:" header (cf COMSAT).
#
# @@@@ saving/restoring messages:
# - Save messages chronologically in original format (with \n) including the RFC arg, separated (ended) by ^L
# - Save also outgoing messages, where the RFC "destuser" is "to:destuser@host"
# - When restoring, use the "to:" prefix to select how to show it.
# - Save msgs separately from settings.
# - (at some point) have a setting for how many/how old msgs to save/restore
#
# @@@@ For sending, need to know our Chaos host name, which might be different from "actual" host name.
# @@@@ May add "ID" operation for cbridge NCP to return useful things like addresses, full hostname, pretty hostname
# @@@@ TODO: Make this a config/parameter here for now.

import sys, re, multiprocessing
from datetime import datetime
from chaosnet import ChaosError, dns_name_of_address, dns_addr_of_name_search, set_dns_resolver_address
from qsend import get_send_message, send_message

# For now, try pyqt6.
# https://www.riverbankcomputing.com/static/Docs/PyQt6/api/qtwidgets/qtwidgets-module.html

# @@@@ Menubar icons don't seem to work in PyQt6, but in PySide6. But threadutil only works in PyQt6. :-(
# They work in pyqt6 on Z2, but not on Puck. 
from PyQt6.QtCore import Qt, QSettings, QPoint, QSize, QUrl, QThread, QTimer
from PyQt6.QtCore import QCommandLineOption, QCommandLineParser, QRegularExpression
from PyQt6.QtWidgets import (QPlainTextEdit, QTextEdit, QMainWindow, QSpacerItem, QSizePolicy)
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QInputDialog,
                             QPushButton, QLabel, QFrame, QSpacerItem, QMessageBox, QComboBox,
                             QColorDialog, QTabWidget, 
                             QSizePolicy, QScrollArea, QLineEdit, QMenuBar, QProgressDialog)
from PyQt6.QtGui import QAction, QRegularExpressionValidator, QColor, QPixmap, QIcon, qGray
from PyQt6.QtMultimedia import QSoundEffect

# Create app already here, so QSettings below work nicely
app = QApplication(sys.argv)
app.setApplicationName("Converse")
app.setOrganizationName("Chaosnet.net")
app.setOrganizationDomain("chaosnet.net")
app.setApplicationVersion("0.0.3")

################ configuration
default_config = dict(# date_color="#ffebee", 
    # @@@@ make a config menu thing for this
    from_net_color="#ffc",
    from_me_color="#e1f5fe",
    background_color="#eee",
    send_message_timeout=5,
    # Sigh.
    dns_search_list=["chaosnet.net","victor.se","dfupdate.se"],
    dns_server="dns.chaosnet.net",
    # @@@@ TEMP HACK until cbridge does ID operation @@@@
    my_chaos_hostname=None,     # None means use IP hostname
    MainWindowSize=QSize(600,400),
    # MainWindowPosition=None,
    beep_sound="/System/Library/Sounds/Ping.aiff",
)

# create/restore settings based on app name etc
settings = QSettings()
# get setting, defaulting to default_config values
def getconf(opt):
    return settings.value(opt, default_config[opt] if opt in default_config else None)

app.setStyleSheet("QMainWindow {"+"background-color: {};".format(getconf('background_color'))+"}")

################  get messages from cbridge

# cf https://github.com/pyqt/examples/blob/_/src/11%20PyQt%20Thread%20example/03_with_threadutil.py
from threading import Thread
from threadutil import run_in_main_thread, CurrentThread
from time import sleep

new_messages = []
def fetch_new_messages(win):
    def add_message(win,uname,host,text):
        sender = ""
        ru, rh = win.remote_user(),win.remote_host()
        if ru is None or rh is None or uname.lower() != ru.lower() or host.lower() != rh.lower():
            # not the same remote as last what's in the destination box
            win.set_destination(uname,host,False) # update the box, but don't switch to it
        sender = "{}@{}".format(uname,host) # show who it's from in the message box
        win.add_message(sender, text, True)
        win.last_other = sender
        # @@@@ optionally beep (setting)
    # The trick: run add_message in the main thread
    am = run_in_main_thread(add_message)
    from getpass import getuser
    me = getuser()
    from socket import getfqdn
    myhost = getconf('my_chaos_hostname') or getfqdn()
    while True:
        try:
            # @@@@ use the remote date spec to show tz offset, if any
            destuser,uname,host,date,text = get_send_message(searchlist=getconf('dns_search_list'))
        except ChaosError as msg:
            print("Error getting Converse messages: {}".format(msg.message), file=sys.stderr)
            # typically no cbridge running, so wait a bit before trying again
            sleep(5)
            continue
        if destuser is None:    # Invalid request
            continue
        # filter out the silly header line that ITS QSEND puts there.
        # @@@@ perhaps check the matches against destuser/myhost?
        m = re.match(r"To: ([\w_.]+) at ([\w.]+)", text)
        if m:
            text = text[m.end():].lstrip()
        if destuser.lower() == me.lower():
            am(win,uname,host,text)
        else:                   # This shouldn't happen, get_send_message checks
            am(win,uname,host,"To: {}@{}\n".format(destuser,myhost)+text)

################ GUI/app

# @@@@ doesn't work on my mac?
def beep():
    effect = QSoundEffect()
    effect.setSource(QUrl.fromLocalFile(getconf('beep_sound')))
    effect.play()

# This makes the box fit the needed height, not more
# https://stackoverflow.com/a/68271889
# @@@@ Change this to do a QPlainTextEdit?
class MsgBox(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        # self.setFont(font)
        self.textChanged.connect(self.autoResize)

    def autoResize(self):
        self.document().setTextWidth(self.viewport().width())
        margins = self.contentsMargins()
        height = int(self.document().size().height() + margins.top() + margins.bottom())
        self.setFixedHeight(height)

    def resizeEvent(self, event):
        self.autoResize()
        super().resizeEvent(event)

    #### this is for keeping track of when we gain focus: then remove dock widget counter
    def focusInEvent(self, event):
        # @@@@ remove dock widget counter
        # find the MainWindow by traversing parentWidget() until isWindow() is true
        # print("focus in",self,event, file=sys.stderr)
        super().focusInEvent(event)

# Automatically scroll to the bottom when things are added etc
# https://stackoverflow.com/a/71283629
class AutoBottomScrollArea(QScrollArea):
    def __init__(self):
        super().__init__()
        self.verticalScrollBar().rangeChanged.connect(self.scrollToBottom)
    def scrollToBottom(self, minVal=None, maxVal=None):
        # Additional params 'minVal' and 'maxVal' are declared because
        # rangeChanged signal sends them, but we set it to optional
        # because we may need to call it separately (if you need).
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

    #### this is for keeping track of when we gain focus: then remove dock widget counter
    def focusInEvent(self, event):
        # @@@@ remove dock widget counter
        # find the MainWindow by traversing parentWidget() until isWindow() is true
        # print("focus in",self,event, file=sys.stderr)
        super().focusInEvent(event)

# @@@@ maybe QPlainTextEdit, for multi-line input.
# @@@@ For validation (ascii only), see answer by Judah Benjamin on
# @@@@ https://www.devasking.com/issue/how-to-restrict-user-input-in-qlineedit-in-pyqt
class MessageInputBox(QLineEdit):
    #### this is for keeping track of when we gain focus: then remove dock widget counter
    def focusInEvent(self, event):
        # @@@@ remove dock widget counter
        # find the MainWindow by traversing parentWidget() until isWindow() is true
        # print("focus in",self,event, file=sys.stderr)
        super().focusInEvent(event)

class DestinationBox(QComboBox):
    #### this is for keeping track of when we gain focus: then remove dock widget counter
    def focusInEvent(self, event):
        # @@@@ remove dock widget counter
        # find the MainWindow by traversing parentWidget() until isWindow() is true
        # print("focus in",self,event, file=sys.stderr)
        super().focusInEvent(event)
  
# New design:
class ConversationTabs(QTabWidget):
    # This holds all the conversations, and keeps track of them
    def __init__(self, parent = None):
        super().__init__(parent)
        self.my_tabs = []
        self.unread_marker = self.make_icon("red")
        # set up currentChanged signal to also change destination_selector, and clear red icon
        self.currentChanged.connect(self.selected_tab_changed)
        # set up tabCloseRequested signal to do close_conversation which also removes from destination_list
        self.tabCloseRequested.connect(self.close_conversation)
        # set up ScrollButtons and IconSize
        self.setUsesScrollButtons(True) # @@@@ until we have West Side tabs
        self.setIconSize(QSize(4,4))    # @@@@ experiment
        self.setTabBarAutoHide(True)    # @@@@ experiment
        # @@@@ at some point make the tabs go west AND horizontal
        # @@@@ add a header (to be replaced) saying "Conversations appear here"

    def set_destbox(self, destbox):
        # These are mutually dependent, so one has to be updated after creation
        self.destination_selector = destbox # need to keep track of this
    def make_icon(self, colorspec):
        pm = QPixmap(12,12)
        pm.fill(QColor(colorspec))
        # print("Made icon from pixmap for color {!r}: {!r}".format(colorspec,pm), file=sys.stderr)
        return QIcon(pm)

    def selected_tab_changed(self,newidx):
        dest = self.tabText(newidx)
        self.setTabIcon(newidx, QIcon()) # clear the red marker
        # Keep destination_list in sync with tab selection
        # I hope this doesn't make things recurse too much...
        if self.destination_selector.currentText() != dest:
            self.destination_selector.select_destination(dest)

    def add_message(self, destination, text, is_from_net):
        c = self.find_conversation(destination)
        if c is None:
            # print("Can't find conversation with {!r}, adding one".format(destination), file=sys.stderr)
            c = self.add_conversation(destination)
        c.add_message(destination, text, is_from_net=is_from_net)
        if c != self.currentWidget():
            # print("Added msg to non-current conversation, marking it as unread", file=sys.stderr)
            self.setTabIcon(self.indexOf(c), self.unread_marker)
        if not app.activeWindow():
            app.alert(self)
        # Return the index of the conversation of the msg
        return self.indexOf(c)

    def add_conversation(self, destination):
        c = ConversationTab()
        c.last_other = destination
        i = self.addTab(c, destination)
        self.setTabToolTip(i, destination)
        # @@@@ also make sure destination is in destination_list
        di = self.destination_selector.find_destination(destination)
        if di < 0:
            self.destination_selector.add_destination(destination)
        return c
    def find_conversation(self, destination):
        # find the conversation for a message destination
        for i in range(self.count()):
            if self.tabText(i).lower() == destination.lower():
                return self.widget(i)
    def select_conversation(self, destination):
        c = self.find_conversation(destination)
        if c:
            # print("Setting current conversation for {} = {!r}".format(destination, c), file=sys.stderr)
            self.setCurrentWidget(c)
        else:
            # print("select_conversation: can't find conversation for {}".format(destination), file=sys.stderr)
            pass
    def remove_conversation(self, destination):
        # remove the whole conversation for a destination, e.g. when closing a tab
        # or removing a destination from the destination_list
        c = self.find_conversation(destination)
        if c:
            i = self.indexOf(c)
            if i >= 0:
                c.clear_conversation()
                self.removeTab(i)
            else:
                print("remove_conversation: Can't find index of conversation {!r} ({})".format(c, destination), file=sys.stderr)
        else:
            print("remove_conversation: Can't find conversation with {}".format(destination), file=sys.stderr)
    def close_conversation(self, idx):
        c = self.widget(idx)
        print("close_conversation: clearing conversation {} ({!r})".format(idx, c), file=sys.stderr)
        c.clear_conversation()
        d = self.tabText(idx)
        print("close_conversation: removing destination {!r}".format(d), file=sys.stderr)
        self.destination_selector.remove_destination(d)
        print("close_conversation: removing tab {}".format(idx), file=sys.stderr)
        self.removeTab(idx)

    def clear_conversation(self, destination):
        c = self.find_conversation(destination)
        if c:
            print("Clearing conversation with {!r}".format(destination), file=sys.stderr)
            c.clear_conversation()
    def clear_all_conversations(self):
        for i in range(self.count()):
            print("Clearing conversation with {!r}".format(self.tabText(i)), file=sys.stderr)
            self.widget(i).clear_conversation()

class ConversationTab(AutoBottomScrollArea):
    def __init__(self, parent = None):
        super().__init__()
        self.prev_msg_datetime = None
        self.last_other = None

        # This holds one conversation in a vertically scrolling container, contains the widgets, set as the centralWidget
        self.widget = QWidget() # widget that contains the collection of Vertical Box
        self.msglayout = QVBoxLayout()  # the vertical box that contains the MsgBoxes
        self.widget.setLayout(self.msglayout)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setWidgetResizable(True)
        # You must add the layout of widget before you call this function; if you add it later, the widget will not be visible
        self.setWidget(self.widget)
        self.init_message_history()

    def add_message(self, other, text, is_from_net=True):
        # If self.prev_msg_time is a different day than today, add a line with today's date
        if self.prev_msg_datetime is None or datetime.now().date() != self.prev_msg_datetime.date():
            self.msglayout.addWidget(self.make_date_marker())
            self.prev_msg_datetime = datetime.now()
        corr = self.make_correspondent_line(other)
        # @@@@ instead, subclass MsgBox for left/right position
        box = MsgBox()
        box.setText(text)
        # Nice corners please!
        # @@@@ consider QSS?
        ss = "border-radius: 7px; border: 1px solid grey;"
        if is_from_net:         # text on the left
            if getconf("from_net_color"):
                ss += "background-color: {};".format(getconf('from_net_color'))
                if qGray(QColor(getconf('from_net_color')).rgba()) < 128:
                    ss += "color: white;"
            align = Qt.AlignmentFlag.AlignLeft
            contents = [box, corr]
        else:                   # on the right
            if getconf("from_me_color"):
                ss += "background-color: {};".format(getconf('from_me_color'))
                if qGray(QColor(getconf('from_me_color')).rgba()) < 128:
                    ss += "color: white;"
            align = Qt.AlignmentFlag.AlignRight
            contents = [corr, box]
        box.setStyleSheet(ss)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        for c in contents:
            row.addWidget(c, alignment=align)
        w = QWidget()
        w.setLayout(row)
        self.msglayout.addWidget(w, alignment=align)

    def clear_conversation(self):
        # clear, but keep it
        # Need to recursively delete widgets.
        # cf "Example 2: Clearing Widgets in a QGridLayout" on https://dnmtechs.com/clearing-widgets-in-pyqt-layout-python-3-programming/
        # similar to https://gist.github.com/GriMel/181db149cc150d903f1a
        # 
        def clear_layout(layout):
            while layout is not None and layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()
                else:
                    clear_layout(item.layout())
        clear_layout(self.msglayout)
        # Then reinitialize it
        self.init_message_history()

    def init_message_history(self):
        h = QLabel()
        h.setTextFormat(Qt.TextFormat.RichText)
        h.setText("<i>Message history</i>")
        self.msglayout.addWidget(h, alignment=Qt.AlignmentFlag.AlignCenter)
        # Keep a stretch at the top of the messages, so new msgs are at the bottom, next to the input box
        self.msglayout.addStretch(1)

    def makeline(self, width=100):
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        line.setMinimumWidth(width)
        return line

    def make_date_marker(self):
        dbox = QHBoxLayout()
        dbox.setContentsMargins(0, 0, 0, 0)
        dbox.addWidget(self.makeline(), alignment=Qt.AlignmentFlag.AlignRight)
        d = QLabel(datetime.now().date().strftime("%e %b %Y"))
        d.setScaledContents(True)
        dbox.addWidget(d, alignment=Qt.AlignmentFlag.AlignCenter)
        dbox.addWidget(self.makeline(), alignment=Qt.AlignmentFlag.AlignLeft)
        dw = QWidget()
        dw.setLayout(dbox)
        # @@@@ consider QSS?
        if getconf("date_color"):
            dw.setStyleSheet('background-color: {};'.format(getconf('date_color')))
        # self.msglayout.addWidget(dw, alignment=Qt.AlignmentFlag.AlignHCenter)
        return dw

    def make_correspondent_line(self, other, time=None):
        if self.last_other is None or other.lower() != self.last_other.lower():
            # New other end, show it together with the time
            tbox = QVBoxLayout()
            tbox.setContentsMargins(0, 0, 0, 0)
            tbox.setSpacing(0)
            tbox.addWidget(QLabel(datetime.now().strftime('%H:%M:%S')))
            tbox.addWidget(QLabel(other))
            time = QWidget()
            time.setLayout(tbox)
            self.last_other = other
        else:
            time = QLabel(datetime.now().strftime('%H:%M:%S'))
        return time

class DestinationSelector(QComboBox):
    def __init__(self, parent = None):
        super().__init__(parent)
        self.tabbar = None
        self.currentIndexChanged.connect(self.current_destination_changed)
        self.setMinimumWidth(300)
        self.setEditable(True)
        self.setDuplicatesEnabled(False)
        self.setInsertPolicy(QComboBox.InsertPolicy.InsertAtTop) # alphabetically?
        self.setValidator(QRegularExpressionValidator(QRegularExpression(r"[\w_.-]+@[\w_.-]+"),self))
    def set_tabbar(self, tb):
        # These are mutually dependent, so one has to be updated after creation
        self.tabbar = tb
    def current_destination_changed(self, newidx):
        if self.tabbar:
            # Keep destination_list in sync with tab selection
            # I hope this doesn't make things recurse too much...
            dest = self.itemText(newidx)
            # print("current_destination_changed: destinations are {!r}".format([self.itemText(i) for i in range(self.count())]), file=sys.stderr)
            # print("current_destination_changed: curr is {}, newidx {} => dest {}".format(self.currentIndex(), newidx, dest), file=sys.stderr)
            if self.currentIndex() != newidx:
                # print("current_destination_changed: new index {} not current ({}), changing it".format(newidx, self.currentIndex()), file=sys.stderr)
                self.setCurrentIndex(newidx)
            c = self.tabbar.find_conversation(dest)
            if c:
                i = self.tabbar.indexOf(c)
                # print("Current dest changed: setting tabbar index {}".format(i), file=sys.stderr)
                self.tabbar.setCurrentIndex(i)
            else:
                print("current_destination_changed: can't find conversation with {}".format(dest), file=sys.stderr)
                pass
    def find_destination(self, dest):
        return self.findText(dest, flags=Qt.MatchFlag.MatchFixedString)
    def add_destination(self, dest):
        if self.find_destination(dest) < 0:
            if self.insertPolicy() == QComboBox.InsertPolicy.InsertAtTop:
                self.insertItem(0, dest)
                settings.setValue('destination_list_index', 0)
            else:           # I assumed this followed the policy, but...
                i = self.addItem(dest)
                settings.setValue('destination_list_index', i)
        else:
            # print("Not adding destination {!r}: already exists".format(dest), file=sys.stderr)
            pass
    def remove_destination(self, dest):
        i = self.find_destination(dest)
        if i >= 0:
            print("Removing destination {} ({}) from destination list".format(i, dest), file=sys.stderr)
            self.removeItem(i)
    def select_destination(self, dest):
        di = self.find_destination(dest)
        if di >= 0:
            self.setCurrentIndex(di)
            settings.setValue('destination_list_index', di)
        else:
            # print("Can't select destination {!r}: not found".format(dest), file=sys.stderr)
            pass
    def edit_destination_list(self):
        pass                    # @@@@ 
    def clear_destination_list(self):
        self.clear()            # @@@@


# Subclass QMainWindow to customize your application's main window
#
# This could/should be a conversation window, i.e. per conversation/destination.
# The thread which reads incoming msgs should keep track of windows
# and give a msg to an existing, or create a new one, depending on the source.
# Alternative: use tabs rather than new windows?
#
# Alternative: make it a "group chat" with all msgs in the same window, and tag all msgs with sender?
# Easier? But who are new msgs for? Still group chat would be nice?
# @@@@ Develop a group chat, but probably separate
class MainWindow(QMainWindow):

    def aboutme(self):
        QMessageBox.about(self, "About Converse", 
                          "<center><b>"+app.applicationName()+" "+app.applicationVersion()+"</b></center><br>"+
                          app.applicationName()+" is a program to have conversations on Chaosnet.<br>"+
                          # "Please see https://"+app.organizationDomain()+".<br>"+
                          "Copyright © 2025 Björn Victor (bjorn@victor.se)")

    def set_message_timeout(self):
        input,ok = QInputDialog.getInt(self,"Set send timeout","Timeout when sending messages",
                                       getconf('send_message_timeout'), min=1, max=30, step=1)
        if ok:
            if input != getconf('send_message_timeout'):
                # avoid saving the default_config value
                settings.setValue('send_message_timeout', input)
        else:
            print("Setting message timeout cancelled", file=sys.stderr)

    def set_dns_server(self):
        input,ok = QInputDialog.getText(self,"DNS server for Chaosnet","Strongly recommended not to change!",
                                       text=getconf('dns_server'))
        if ok and input and len(input.strip()) > 0:
            s = input.strip()
            if s == getconf('dns_server'):
                # avoid saving the default_config value
                return
            r = None
            if "." in s and re.match(r"^[\w_.-]+[^.]$", s):
                print("Setting DNS server:",s, file=sys.stderr)
                if set_dns_resolver_address(s) is None:
                    # can fail e.g. if the name isn't actually in DNS
                    r = QMessageBox.warning(self,"Error","Failed setting DNS server",
                                            buttons=QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.RestoreDefaults)
                else:
                    settings.setValue('dns_server', s)
            else:
                print("Bad syntax for DNS server: {!r}".format(s), file=sys.stderr)
                r = QMessageBox.warning(self,"Syntax error","Domain name syntax error",
                                        buttons=QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.RestoreDefaults)
            if r == QMessageBox.StandardButton.RestoreDefaults:
                print("Restoring DNS server default:",default_config['dns_server'], file=sys.stderr)
                # Clear the settings value, so the default_config is used instead
                settings.setValue('dns_server',None)
                if set_dns_resolver_address(default_config['dns_server']) is None:
                    QMessageBox.critical(self,"Error","Failed setting default DNS server!")
        else:
            print("Setting DNS server cancelled", file=sys.stderr)

    def set_dns_search_list(self):
        while True:
            input,ok = QInputDialog.getMultiLineText(self,"Domains to search in DNS","Domain list (one per line):",
                                         text="\n".join(getconf('dns_search_list')))
            if ok and input and len(input.strip()) > 0:
                dlist = [d.strip() for d in input.strip().split("\n")]
                if dlist == default_config['dns_search_list']:
                    # avoid saving the default_config value
                    return
                badd = next((d for d in dlist if not("." in d and re.match(r"^[\w_.-]+[^.]$",d))),None)
                if badd:
                    response = QMessageBox.warning(self,"Syntax error","Domains should have '.' in them: "+badd,
                                                   buttons=QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Cancel)
                    if response == QMessageBox.StandardButton.Cancel:
                        print("Cancelled DNS search list setting", file=sys.stderr)
                        return
                else:
                    print("Setting DNS search list:",dlist, file=sys.stderr)
                    settings.setValue('dns_search_list',dlist)
                    return
            else:
                print("Cancelled DNS search list setting", file=sys.stderr)
                return

    def make_icon(self, colorspec):
        # @@@@ make the icon have a thin border to make it stand out in the menu
        pm = QPixmap(12,12)
        pm.fill(QColor(colorspec))
        # print("Made icon from pixmap for color {!r}: {!r}".format(colorspec,pm), file=sys.stderr)
        return QIcon(pm)
        
    def edit_background_color(self, cf_name):
        print("Getting a color setting for {} (default {})".format(cf_name,getconf(cf_name)), file=sys.stderr)
        color = QColorDialog.getColor(QColor(getconf(cf_name)), self)
        if color.isValid() and color.name() != getconf(cf_name):
            print("Got a color: {} ({!r})".format(color.name(),color), file=sys.stderr)
            settings.setValue(cf_name, color.name())
            return color.name()

    def set_background_color(self, color=None):
        c = self.edit_background_color('background_color') if not color else color
        if c:
            settings.setValue('background_color',c)
            self.background_color_action.setIcon(self.make_icon(c))
            app.setStyleSheet("QMainWindow{"+"background-color: {};".format(c)+"}")
       
    def set_background_color_from_me(self, color=None):
        c = self.edit_background_color('from_me_color') if not color else color
        if c:
            i = self.make_icon(c)
            # print("Setting icon for {!r} to {!r}".format(self.from_me_color_action,i), file=sys.stderr)
            self.from_me_color_action.setIcon(i)
            # @@@@ go though all messages and change the color?
    def set_background_color_from_net(self, color=None):
        c = self.edit_background_color('from_net_color') if not color else color
        if c:
            i = self.make_icon(c)
            # print("Setting icon for {!r} to {!r}".format(self.from_net_color_action,i), file=sys.stderr)
            self.from_net_color_action.setIcon(i)
            # @@@@ go though all messages and change the color?

    def edit_destination_list(self):
        dlist = [self.cbox.itemText(i) for i in range(self.cbox.count())]
        while True:
            input,ok = QInputDialog.getMultiLineText(self,"Edit destination menu","user@host (one per line)",
                                         text="\n".join(dlist))
            if ok and input and len(input.strip()) > 0:
                new_dlist = [d.strip() for d in input.strip().split("\n")]
                badd = next((d for d in new_dlist if not re.match(r"^[\w_.-]+@[\w_.-]+$",d)),None)
                if badd:
                    response = QMessageBox.warning(self,"Syntax error","Destination should be user@host: "+badd,
                                                   buttons=QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Cancel)
                    if response == QMessageBox.StandardButton.Cancel:
                        print("Cancelled editing destination list", file=sys.stderr)
                        return
                else:
                    print("Setting destination list:",new_dlist, file=sys.stderr)
                    self.cbox.clear()
                    self.cbox.insertItems(0,new_dlist)
                    settings.setValue('destination_list',new_dlist)
                    # @@@@ what to set destination_list_index to?
                    print("Settings status: {!r}".format(settings.status()), file=sys.stderr)
                    if settings.status() != QSettings.Status.NoError:
                        QMessageBox.warning(self,"Settings error","Settings could not be saved: {!r}".format(settings.status()))
                    return
            else:
                print("Cancelled editing destination list", file=sys.stderr)
                return

    def reset_destinations(self):
        self.cbox.clear()
        settings.setValue('destination_list',[])
        settings.setValue('destination_list_index',0)

    def init_message_history(self):
        h = QLabel()
        h.setTextFormat(Qt.TextFormat.RichText)
        h.setText("<i>Message history</i>")
        self.msglayout.addWidget(h, alignment=Qt.AlignmentFlag.AlignCenter)
        # Keep a stretch at the top of the messages, so new msgs are at the bottom, next to the input box
        self.msglayout.addStretch(1)

    def clear_all_conversations(self):
        self.tbar.clear_all_conversations()
    def remove_all_conversations(self):
        self.tbar.remove_all_conversations()
    def clear_current_conversation(self):
        currdest = self.tbar.tabText(self.tbar.currentIndex())
        if currdest and len(currdest) > 0:
            print("Clearing conversation with {}".format(currdest), file=sys.stderr)
            self.tbar.clear_conversation(currdest)
    def remove_current_conversation(self):
        currdest = self.tbar.tabText(self.tbar.currentIndex())
        if currdest and len(currdest) > 0:
            print("Removing conversation with {}".format(currdest), file=sys.stderr)
            self.tbar.remove_conversation(currdest)
    def remove_current_destination(self):
        currdest = self.cbox.currentText()
        if currdest and len(currdest) > 0:
            print("Removing destination {}".format(currdest), file=sys.stderr)
            self.cbox.remove_destination(currdest)


    def reset_settings(self):
        # Reset settings
        for s in list(default_config.keys()) + ["MainWindowSize", "MainWindowPosition"]:
            settings.setValue(s,default_config[s] if s in default_config else None)
        # Also update effect of settings: background colors
        app.setStyleSheet("QMainWindow{"+"background-color: {};".format(getconf('background_color'))+"}")
        self.set_background_color_from_net(getconf('from_net_color'))
        self.set_background_color_from_me(getconf('from_me_color'))
        # Resize to default
        wsz = default_config['MainWindowSize']
        self.resize(wsz)
        if getconf('MainWindowPosition'):
            # If there is a default, move there
            self.move(getconf('MainWindowPosition'))
        else:
            # Else find the middle of the screen we're on
            scr = app.screenAt(self.pos())
            sz = scr.size()
            self.move(QPoint(round((sz.width()-wsz.width())/2), round((sz.height()-wsz.height())/2)))

    def sendit(self):
        if len(self.input.text().strip()) == 0:
            # just noop. This is slightly better than disabling the button, which makes it almost invisible (on macOS).
            return
        if not self.remote_host() or not self.remote_user():
            # @@@@ Beep
            QMessageBox.critical(self,"Error","Destination user/host unknown!",
                                 buttons=QMessageBox.StandardButton.Ok)
            return
        # Expand destination host (sigh, searchlist configuration...)
        destaddr = dns_addr_of_name_search(self.remote_host(),searchlist=getconf('dns_search_list'))
        if destaddr is None or len(destaddr) < 1:
            QMessageBox.critical(self,"Error","Destination host {!r} unknown on Chaosnet".format(self.remote_host()),
                                 buttons=QMessageBox.StandardButton.Ok)
            return
        if len(self.input.text()) > 0:
            u,h = self.remote_user(), self.remote_host()
            desthost = dns_name_of_address(destaddr[0])
            if desthost and h != desthost:
                print("Setting dest to {!r} (canonical name of {!r})".format(desthost, h), file=sys.stderr)
                h = desthost
            print("Setting destination {}@{}".format(u,h), file=sys.stderr)
            self.set_destination(u,h, True) # update dest, and switch to it
            # first lock the input, send it, and when it's sent, unlock (in case it takes time)
            print("Sending to {}@{}: {!r}".format(u,h, self.input.text()), file=sys.stderr)
            self.input.setReadOnly(True)
            try:
                other = "{}@{}".format(u,h)
                # @@@@ need a cancel button, and a timeout setting
                # @@@@ need to run send_message in another thread:
                # cf https://www.pythonguis.com/tutorials/multithreading-pyside6-applications-qthreadpool/
                # cf https://www.riverbankcomputing.com/static/Docs/PyQt6/api/qtwidgets/qprogressdialog.html
                send_message(u,h, self.input.text(), timeout=getconf('send_message_timeout'),myhostname=getconf('my_chaos_hostname'))
                ix = self.tbar.add_message(other, self.input.text(), is_from_net=False)
                self.tbar.select_conversation(other)
                # and clear the input field
                self.input.clear()
            except ChaosError as m:
                # @@@@ Beep
                print("Chaosnet error: {!r}".format(m.message), file=sys.stderr)
                QMessageBox.critical(self,"Chaosnet Error","Error from host {}:<br>{}".format(self.remote_host(),m.message.rstrip("\0x00")),
                                     buttons=QMessageBox.StandardButton.Ok)
            self.input.setReadOnly(False)

    def add_message(self, other, text, is_from_net):
        self.tbar.add_message(other, text, is_from_net=is_from_net)

    def remote_user(self):
        try:
            u,h = self.cbox.currentText().split("@")
            return u
        except ValueError:
            return None
    def remote_host(self):
        try:
            u,h = self.cbox.currentText().split("@")
            return h
        except ValueError:
            return None

    def set_destination(self, user=None, host=None, switch=True):
        if user is None or user == "":
            print("Invalid destination user {!r}".format(user), file=sys.stderr)
        elif host is None or host == "":
            print("Invalid destination host {!r}".format(host), file=sys.stderr)
        else:
            # Since the text might not have been "activated" yet, just entered, add it to the menu
            di = self.cbox.find_destination(self.cbox.currentText())
            if di < 0:
                if self.cbox.insertPolicy() == QComboBox.InsertPolicy.InsertAtTop:
                    self.cbox.insertItem(0, self.cbox.currentText())
                    di = 0
                else:           # I assumed this followed the policy, but...
                    di = self.cbox.addItem(self.cbox.currentText())
                settings.setValue('destination_list_index',di)
                if switch:
                    self.cbox.setCurrentIndex(di)
                    settings.setValue('destination_list',[self.cbox.itemText(i) for i in range(self.cbox.count())])
            else:
                if switch and self.cbox.currentIndex() != di:
                    # print("set_destination: changing index from {} to {}".format(self.cbox.currentIndex(), di), file=sys.stderr)
                    self.cbox.setCurrentIndex(di)
                    settings.setValue('destination_list_index', di)
                else:
                    # print("set_destination: not changing index from {} ({}, {})".format(self.cbox.currentIndex(), self.cbox.currentText(), switch), file=sys.stderr)
                    pass
                if switch and self.tbar.tabText(self.tbar.currentIndex()).lower() != self.cbox.currentText().lower():
                    # print("set_destination: switching conversation", file=sys.stderr)
                    self.tbar.select_conversation(self.cbox.currentText())

    def closeEvent(self,event):
        settings.setValue("MainWindowSize",self.size())
        settings.setValue("MainWindowPosition",self.pos())
        # event.accept()
        super().closeEvent(event)

    # never activated?
    def focusChange(self,old,new):
        print("Focus change: from",old,"to",new, file=sys.stderr)

    def init_menus(self):
        def make_action(title, handler, shortcut=None, icon=None):
            act = QAction(title, self)
            act.triggered.connect(handler)
            if shortcut is not None:
                act.setShortcut(shortcut)
            if icon is not None:
                # print("Setting icon for {!r} to {!r}".format(title,icon), file=sys.stderr)
                act.setIcon(icon)
            return act
        # Create the application menu
        self_menu = self.menuBar()
        my_menu = self_menu.addMenu(app.applicationName())
        aboutaction = make_action("About {}".format(app.applicationName()), self.aboutme)
        my_menu.addAction(aboutaction)
        my_menu.addAction(make_action("Send message", self.sendit, shortcut="Ctrl+S"))
        settings_menu = self_menu.addMenu("Settings")
        settings_menu.addAction(make_action("Edit destination menu", self.edit_destination_list))
        settings_menu.addAction(make_action("Clear destination menu", self.reset_destinations))
        settings_menu.addAction(make_action("Clear all conversations", self.clear_all_conversations))
        settings_menu.addAction(make_action("Remove all conversations", self.remove_all_conversations))
        settings_menu.addSeparator()
        settings_menu.addAction(make_action("Set send timeout...", self.set_message_timeout))
        settings_menu.addAction(make_action("Set domain search list...", self.set_dns_search_list))
        settings_menu.addAction(make_action("Set DNS server...", self.set_dns_server))
        settings_menu.addSeparator()
        self.background_color_action = make_action("Edit background color...", self.set_background_color,
                                                   icon=self.make_icon(getconf('background_color')))
        settings_menu.addAction(self.background_color_action)
        self.from_net_color_action = make_action("Edit net message background color...", 
                                                 self.set_background_color_from_net,
                                                 icon=self.make_icon(getconf('from_net_color')))
        settings_menu.addAction(self.from_net_color_action)
        self.from_me_color_action = make_action("Edit my message background color...", 
                                                self.set_background_color_from_me,
                                                icon=self.make_icon(getconf('from_me_color')))
        settings_menu.addAction(self.from_me_color_action)
        settings_menu.addAction(make_action("Reset all settings", self.reset_settings))
        
        conv_menu = self_menu.addMenu("Conversation")
        conv_menu.addAction(make_action("Clear conversation", self.clear_current_conversation))
        conv_menu.addAction(make_action("Remove conversation", self.remove_current_conversation))
        conv_menu.addAction(make_action("Remove destination", self.remove_current_destination))

    def init_layout_and_boxes(self):
        # Put the messages in separate conversation tabs
        self.tbar = ConversationTabs()
        
        # now the part for the input and Send button
        hlayout = QHBoxLayout()
        self.sendbutton = QPushButton("Send", self)
        self.sendbutton.setDefault(True) # Make it a nice big button
        # Disabling the button makes it almost invisible (on macOS). Instead have sendit handle it.
        # self.sendbutton.setEnabled(False)
        self.sendbutton.clicked.connect(self.sendit)
        hlayout.addWidget(self.sendbutton)

        self.input = MessageInputBox()
        # Set a validator to make the returnPressed only happen when non-empty, and only accept ASCII
        self.input.setValidator(QRegularExpressionValidator(QRegularExpression("[[:ascii:]]+"),self.input))
        self.input.returnPressed.connect(self.sendit)
        hlayout.addWidget(self.input)

        destlayout = QHBoxLayout()
        destlayout.addWidget(QLabel("Destination:"), alignment=Qt.AlignmentFlag.AlignLeft)
        self.cbox = DestinationSelector(self)
        self.cbox.set_tabbar(self.tbar) # tie them together
        self.tbar.set_destbox(self.cbox)
        destlayout.addWidget(self.cbox, alignment=Qt.AlignmentFlag.AlignLeft)
        destlayout.addStretch(1)

        # The top-level layout: messages followed by input
        toplayout = QVBoxLayout()
        toplayout.addWidget(self.tbar)
        toplayout.addLayout(destlayout)
        toplayout.addLayout(hlayout)
        topwidget = QWidget()
        topwidget.setLayout(toplayout)

        self.setCentralWidget(topwidget)

        self.input.setFocus()   # after showing it (by setCentralWidget)

    def __init__(self):
        super().__init__()
        self.prev_msg_datetime = None
        self.last_other = None

        self.setWindowTitle("Chaosnet Converse")
        # Initialize settings
        set_dns_resolver_address(getconf('dns_server'))
        self.resize(settings.value("MainWindowSize",getconf('MainWindowSize')))    # @@@@ make this depend on font size
        if settings.value("MainWindowPosition"):
            self.move(settings.value("MainWindowPosition"))

        # initialize layout etc
        self.init_layout_and_boxes()
        if settings.value('destination_list'):
            self.cbox.insertItems(0,settings.value('destination_list'))
        if settings.value('destination_list_index'):
            self.cbox.setCurrentIndex(settings.value('destination_list_index'))

        # initialize menus
        self.init_menus()

# https://www.pythonguis.com/faq/command-line-arguments-pyqt6/
def parse_args(app):
    parser = QCommandLineParser()
    parser.addHelpOption()
    parser.addVersionOption()
    copt = QCommandLineOption(["c","chaoshost"],"My Chaosnet hostname","chaosname")
    # @@@@ add --verbose, and use it for non-debug-but-possibly-relevant printouts
    parser.addOption(copt)
    parser.process(app)
    return parser.value(copt)

if __name__ == '__main__':
    chost = parse_args(app)
    if chost:
        from socket import getfqdn
        if chost.lower() != getfqdn().lower() and dns_addr_of_name_search(getfqdn()):
            # maybe refuse
            print("%% Spoofing Chaosnet hostname", file=sys.stderr)
        if re.match(r"^[\w_.-]+[^.]$", chost) and dns_addr_of_name_search(chost):
            print("Setting Chaosnet hostname {!r}".format(chost), file=sys.stderr)
            default_config['my_chaos_hostname'] = chost
        else:
            print("Bad Chaosnet hostname {!r}".format(chost), file=sys.stderr)
            exit(1)

    try:
        # Create a Qt widget, which will be our window.
        window = MainWindow()
        window.show()

        # Run the SEND server thread
        thread = Thread(target=fetch_new_messages, args=(window,), daemon=True)
        thread.start()

        # Start the event loop.
        app.exec()
    except RuntimeError as m:
        print(m, file=sys.stderr)
