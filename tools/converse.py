#!/usr/bin/env python3
#
# Copyright © 2025-2026 Björn Victor (bjorn@victor.se)
# This is a Converse (i.e. SEND) client/server, vaguely reminiscent of Converse on LISPM.
# It can be used to send/receive text messages between users on the Chaosnet.

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
# - make watchers stop more quickly (e.g. when quitting the program).
#   Now they only stop at the end of a full round, which can take a few seconds. Should use conn.abort() like
#   the MessageReceiver.
# - keep order of conversations in synch with destination list: add at top (except initially), and after editing
# -- easier/deterministic: make them alphabetically ordered (possibly per host, alphabetically)
# - maybe (optionally) make collect_all_destinations run periodically?
# -- or maybe go all the way and include a NAME/FINGER display you can click on to start conversations?
# - do actual sending in a separate thread, interruptible by Cancel button. Cf how MessageReceiver works, but not persistent.
# - Update documentation (constantly). Perhaps also "technical doc"?
# - add a "destination status" pane (at top? or the status bar?), showing finger/name status with quick/click update
# -- save whole NameDict/FingerDict result (in addition to parsed idle time) so it is easy to make this.
# - left-adjust labels in tabs?
# - when msgs received while non-focused app, don't scroll up (or mark them as unread, somehow)
# - dock icon with counter for unseen msgs (https://doc.qt.io/qtforpython-6/overviews/qtdoc-appicon.html)
# - perhaps handle "private" networks (avoid DNS)
# - Tab backgrounds are grey (#ccc) when running in Python, white when running the app. Can't find out how to change this??
# - Use some better method for changing color settings than prepending to the app.styleSheet.
#   This works, as long as you don't change the settings very many times in one session.
# Configuration:
# - tabs left/right?
# - sounds
# - receiver on/off (related to if the screen is on, or idle, or ...)
# Future features: autoreply, idle detection, ignore lists, user aliases...

# SEND protocol message format (https://chaosnet.net/amber.html#Send):
# - RFC arg: destinationUsername
# - line 1: from@host date-and-time
# - rest: message. ITS starts it with "To:" header (cf COMSAT), TOPS-20 has From: and Date:. (We remove that.)
#
# @@@@ Notifications:
# Add notifications for dest/host status changes, perhaps if app is not frontmost?
# Optionally notify the Converse user when destination user@host comes online/goes offline? (cf https://jorricks.github.io/macos-notifications/, https://stackoverflow.com/questions/17651017/python-post-osx-notification)
# Optionally notify when a userid (e.g EJS) comes online at any host?
# Notifications: start off with terminal-notifier (https://github.com/julienXX/terminal-notifier)?


import sys, re, os, time
from datetime import datetime, timezone, timedelta
from chaosnet import ChaosSocketError, ChaosError, CLSError, dns_name_of_address, dns_addr_of_name_search, set_dns_resolver_address, local_domain, get_dns_host_info
from qsend import get_send_message, send_message, parse_send_message, make_send_message
from watcher import ChaosUserWatcher, PersistentWorker
from enum import auto, StrEnum
# pip3 install nocasedict (see https://github.com/pywbem/nocasedict)
from nocasedict import NocaseDict

# For now, use pyqt6.
from PyQt6.QtCore import Qt, QSettings, QPoint, QSize, QUrl, QThread, QTimer, qInfo, qDebug, qWarning, QRect, QSysInfo, QDir
from PyQt6.QtCore import QCommandLineOption, QCommandLineParser, QRegularExpression, QStandardPaths
from PyQt6.QtWidgets import (QPlainTextEdit, QTextEdit, QMainWindow, QSpacerItem, QSizePolicy)
from PyQt6.QtWidgets import (QApplication, QWidget, QWidgetItem, QVBoxLayout, QHBoxLayout, QInputDialog,
                             QPushButton, QLabel, QFrame, QSpacerItem, QMessageBox, QComboBox,
                             QColorDialog, QTabWidget, QGroupBox, QProxyStyle, QTabBar,
                             QStyle, QStylePainter, QStyleOptionTab, QStyleOptionTabWidgetFrame,
                             QSizePolicy, QScrollArea, QLineEdit, QMenuBar, QProgressDialog,
                             QFileDialog)
from PyQt6.QtGui import QAction, QRegularExpressionValidator, QColor, QPixmap, QIcon, qGray
from PyQt6.QtMultimedia import QSoundEffect

# Create app already here, so QSettings below work nicely
app = QApplication(sys.argv)
app.setApplicationName("Converse")
app.setOrganizationName("Chaosnet.net")
app.setOrganizationDomain("chaosnet.net")
app.setApplicationVersion("0.10.5")

################ Default configuration
debug = False
verbose = False
reset_on_startup = False

default_config = dict(
    # Colors
    # date_color="#ffebee", 
    from_net_color="#ffc",
    from_me_color="#e1f5fe",
    background_color="#eee",
    host_up_color="#aaa",       # Host is up (but user not detected)
    active_icon_color="lightgreen", # User is non-idle
    idle_icon_color="yellow",    # User is idle for a while
    away_icon_color="black",     # User is (probably) away
    # Other settings
    send_message_timeout=5,     # seconds
    restore_conversation_tabs=True,
    multi_line_messages=False,
    multi_line_message_lines=3,
    watcher_enabled=True,
    watcher_interval=5,         # minutes (unless debug: seconds)
    idle_limit=10,              # more than this means idle
    away_limit=2*60,            # more than this means away
    default_conversation_save_file=".converse-messages", # @@@@ should probably be different for non-unix systems
    save_restore_messages_enabled=False,
    # Sigh. DNS is re-used everywhere, but needs search list, which isn't global. This is somewhat reasonable.
    dns_search_list=[local_domain(), "Chaosnet.net"],
    dns_server="DNS.Chaosnet.net",
    MainWindowSize=QSize(650,400), # @@@@ make this depend on font size @@@@ make font configurable?
    # MainWindowPosition=None,
    # Sounds:
    sound_effects=True,
    message_incoming_sound="/System/Library/Sounds/Frog.aiff",
    message_sent_sound="/System/Library/Sounds/Morse.aiff",
    alert_sound="/System/Library/Sounds/Ping.aiff",
    # This is not a persistent setting - see the "-c" option
    my_chaos_hostname=None,     # None means use IP hostname
)

# create/restore settings based on app name etc
settings = QSettings()
# get setting, defaulting to default_config values
def getconf(opt):
    return settings.value(opt, default_config[opt] if opt in default_config else None)

app.setStyleSheet(#"QTabBar {background-color: #e8e8e8;}\n"+ # Has no effect in the pyinstaller app, which is where it's needed
    "QTabWidget::tab-bar {left : 0;}\n"+ # On macOS, tabs are normally vertically centered, this top-aligns them
    "MessageDisplayBox { border-radius: 7px; border: 1px solid grey; }\n"+
    "QMainWindow {"+"background-color: {};".format(getconf('background_color'))+"}\n")

################ GUI/app

def beep(type='alert'):
    if not getconf('sound_effects'):
        return
    if QSysInfo.productType() == "macos":
        # Background, otherwise it takes noticable time
        os.system("afplay {} &".format(getconf('{}_sound'.format(type))))
    else:
        # @@@@ doesn't work on my mac? try QApplication.beep?
        effect = QSoundEffect()
        effect.setSource(QUrl.fromLocalFile(getconf('{}_sound'.format(type))))
        effect.play()

# Use this to periodically check if screen is locked, and then pause watchers
def screen_is_locked():
    if QSysInfo.productType() == "macos":
        # cf https://stackoverflow.com/a/79516857/32213645
        return os.system("/usr/sbin/ioreg -n Root -d1 | grep IOConsoleLocked | grep -q ' = Yes'") == 0
    else:
        return False

# @@@@ Change this to do a QPlainTextEdit?
class MessageDisplayBox(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        # self.setFont(font)
        self.textChanged.connect(self.autoResize)

    # This makes the box fit the needed height, not more
    # https://stackoverflow.com/a/68271889
    def autoResize(self):
        self.document().setTextWidth(self.viewport().width())
        margins = self.contentsMargins()
        height = int(self.document().size().height() + margins.top() + margins.bottom())
        self.setFixedHeight(height)

    def resizeEvent(self, event):
        self.autoResize()
        super().resizeEvent(event)

# subclass MessageDisplayBox for left/right position
class MessageDisplayBoxLeft(MessageDisplayBox):
    pass
class MessageDisplayBoxRight(MessageDisplayBox):
    pass

# One-line message input
class MessageInputBox(QLineEdit):
    def toPlainText(self):
        return self.text()      # compatibility with QPlainTextEdit
# Multi-line input
class MessageInputMultiLine(QPlainTextEdit):
    def __init__(self):
        super().__init__()
        # This lacks .setValidator, so set one up manually
        self.textChanged.connect(self.validate_ascii_text)

    def setup_height(self, nlines=None):
        if nlines is None:
            nlines = getconf('multi_line_message_lines')
        self.setFixedHeight(nlines*self.fontMetrics().lineSpacing())

    def validate_ascii_text(self):
        # validate ascii, and filter non-ascii
        txt = self.toPlainText()
        i = 0
        c = next((c for c in txt[i:] if ord(c) > 127),None)
        while c is not None:
            # @@@@ Perhaps put this in the error_pane?
            # print("Bad char in input: {!r}".format(c), file=sys.stderr)
            # @@@@ Perhaps make a "dead key" sound?
            p = txt.find(c)
            txt = txt[:p]+txt[p+1:]
            i = p+1
            c = next((c for c in txt[i:] if ord(c) > 127),None)
        # Save cursor (position)
        if i > 0:
            cursor = self.textCursor()
            self.setPlainText(txt) # replace text, moving cursor to beginning
            self.setTextCursor(cursor) # move cursor back

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

# This makes the tabs appear on the West (left) side *and* horizontally.
# https://github.com/mauriliogenovese/PySide6_VerticalQTabWidget/blob/main/PySide6_VerticalQTabWidget/VerticalQTabWidget.py
class ConversationTabBar(QTabBar):
    def __init__(self):
        super().__init__()
        # @@@@ super weird, but necessary, otherwise only the elision is visible. Further workaound would be needed. Check the sources?
        self.setElideMode(Qt.TextElideMode.ElideNone)
        
    def tabSizeHint(self, index):
        size = super().tabSizeHint(index)
        size.transpose()
        return size

    def paintEvent(self, event):
        painter = QStylePainter(self)
        option = QStyleOptionTab()
        for index in range(self.count()):
            self.initStyleOption(option, index)
            # The test on style doesn't quite work, unfortunately. Test OS instead.
            if QSysInfo.productType() in ["macos","darwin"]: # QApplication.style().objectName() == "macos":
                option.shape = QTabBar.Shape.RoundedNorth    # this magically affects the highlight of selected tab
                option.position = QStyleOptionTab.TabPosition.Beginning
            else:
                option.shape = QTabBar.Shape.RoundedWest
            painter.drawControl(QStyle.ControlElement.CE_TabBarTabShape, option)
            option.shape = QTabBar.Shape.RoundedNorth
            painter.drawControl(QStyle.ControlElement.CE_TabBarTabLabel, option)

class ConversationTabs(QTabWidget):
    # This holds all the conversations, and keeps track of them

    destwatcher = None          # Destination watcher
    messages_unread = None      # dict dest -> any_messages_unread? (or number_of_messages_unread?)

    def __init__(self, parent = None):
        super().__init__(parent)
        self.messages_unread = NocaseDict()
        self.messages_unread_disabled = False
        self.unread_marker = self.make_icon("red")
        self.destination_selector = None

        # make the tabs go west AND horizontal
        self.setTabBar(ConversationTabBar())
        self.setTabPosition(QTabWidget.TabPosition.West)
        # set up currentChanged signal to also change destination_selector, and clear red icon
        self.currentChanged.connect(self.selected_tab_changed)
        # set up tabCloseRequested signal to do close_conversation which also removes from destination_list
        self.tabCloseRequested.connect(self.close_conversation)
        # set up ScrollButtons and IconSize
        # self.setUsesScrollButtons(True) # @@@@ enable this if not using West Side Tabs
        self.setIconSize(QSize(6,6))    # This is for the red dot etc.
        # add a header (to be replaced) saying "Conversations appear here"
        self.dummy_page = self.make_dummy_page()
        self.add_dummy_page()

    # https://gist.github.com/kihoon71/521f12ba7887875a25c756cc9e7aa2fa
    def paintEvent(self, event):
        painter = QStylePainter(self)
        option = QStyleOptionTabWidgetFrame()
        self.initStyleOption(option)
        option.rect = QRect(QPoint(self.tabBar().geometry().width(), 0),
                            QSize(option.rect.width(), option.rect.height()))
        painter.drawPrimitive(QStyle.PrimitiveElement.PE_FrameTabWidget, option)

    def add_dummy_page(self):
        if debug:
            qDebug("Adding dummy page")
        self.setTabBarAutoHide(True) # hide the silly "tab header"
        self.addTab(self.dummy_page,"No conversations active")
    def remove_dummy_page(self):
        if self.is_dummy_page():
            if debug:
                qDebug("Removing dummy page")
            self.removeTab(0)
        self.setTabBarAutoHide(False) # show also single tab headers
    def is_dummy_page(self):
        return self.count() == 1 and self.currentWidget() == self.dummy_page
    def make_dummy_page(self):
        w = QWidget()
        l = QVBoxLayout()
        w.setLayout(l)
        l.addWidget(QLabel("<b>Conversations appear here.</b>"))
        l.addWidget(QLabel("<ol><li>Use the Destination field to select where to send a message, <li>fill in the text in the input field below it, and <li>press the Send button to send it.</ol>"))
        l.addStretch(1)
        return w

    def set_destbox(self, destbox):
        # These are mutually dependent, so one has to be updated after creation
        self.destination_selector = destbox # need to keep track of this
    def set_watcher(self, watcher):
        # these too
        self.destwatcher = watcher
    def make_icon(self, colorspec):
        pm = QPixmap(12,12)
        pm.fill(QColor(colorspec))
        # print("Made icon from pixmap for color {!r}: {!r}".format(colorspec,pm), file=sys.stderr)
        return QIcon(pm)

    def set_messages_unread_disabled(self, value):
        self.messages_unread_disabled = value
    def messages_unread_for_dest(self, dest):
        if self.messages_unread_disabled:
            return False
        val = self.messages_unread is not None and dest in self.messages_unread and self.messages_unread[dest]
        return val
    def set_messages_unread_for_dest(self, dest, value):
        if self.messages_unread_disabled:
            return
        if self.messages_unread is None:
            self.messages_unread = NocaseDict()
        self.messages_unread[dest] = value
    def set_messages_unread_for_all(self, value):
        for d in self.messages_unread.keys():
            self.set_messages_unread_for_dest(d, value)
            self.destwatcher.update_dest_icon(d)

    def selected_tab_changed(self,newidx):
        dest = self.tabText(newidx)
        # update based on Watcher status, clearing red marker
        if len(dest) > 0 and self.messages_unread_for_dest(dest) and self.destwatcher:
            self.set_messages_unread_for_dest(dest, False)
            self.destwatcher.update_dest_icon(dest)
        # self.setTabIcon(newidx, QIcon()) # clear the red marker
        # Keep destination_list in sync with tab selection
        # I hope this doesn't make things recurse too much...
        if self.destination_selector is not None and self.destination_selector.currentText() != dest:
            self.destination_selector.select_destination(dest)

    def set_conversation_tooltip(self, conv, tt):
        i = self.indexOf(conv)
        if i >= 0:
            self.setTabToolTip(i, tt)
    def set_conversation_icon(self, conv, icon):
        i = self.indexOf(conv)
        if i >= 0:
            self.setTabIcon(i, icon)
    def get_conversation_icon(self, conv):
        i = self.indexOf(conv)
        if i >= 0:
            self.tabIcon(i)
    def update_all_icons(self):
        if self.is_dummy_page():
            qDebug("update_all_icons: have dummy page, punting")
            return
        for i in range(self.count()):
            d = self.tabText(i)
            if not self.messages_unread_for_dest(d):
                qDebug("update_all_icons: updating {}".format(d))
                self.destwatcher.update_dest_icon(d)
            else:
                qDebug("update_dest_icon: not updating {} - unread".format(d))

    def add_message(self, destination, date, diffhours, text, is_from_net):
        c = self.find_conversation(destination)
        if c is None:
            qDebug("Can't find conversation with {!r}, adding one".format(destination))
            c = self.add_conversation(destination)
        qDebug("Adding msg for {!r} to {!r}".format(destination,c))
        c.add_message(destination, date, diffhours, text, is_from_net=is_from_net)
        if self.destwatcher.get_status_for_dest(destination) != self.destwatcher.IdleLevel.ACTIVE:
            # If we user isn't known to be active, check if they are now?
            self.destwatcher.refresh_status_for_dest(destination)
        # @@@@ switch to c if there is nothing in the input? (option?)
        if c != self.currentWidget():
            qDebug("Added msg to non-current conversation {}, marking it as unread".format(destination))
            self.set_messages_unread_for_dest(destination, True)
            if not self.messages_unread_disabled:
                self.set_conversation_icon(c, self.unread_marker)
        else:
            qDebug("Added msg to current conversation {}, marking it as read".format(destination))
            self.set_messages_unread_for_dest(destination, False)
            self.destwatcher.update_dest_icon(destination)
        if not app.activeWindow():
            app.alert(self)
        # Return the index of the conversation of the msg
        return self.indexOf(c)

    def add_conversation(self, destination):
        c = self.find_conversation(destination)
        if c:
            return c
        self.remove_dummy_page()
        c = ConversationTab()
        c.last_other = destination
        i = self.addTab(c, destination)
        self.setTabToolTip(i, destination)
        # also make sure destination is in destination_list
        di = self.destination_selector.find_destination(destination)
        if di < 0:
            qDebug("Adding destination {!r}".format(destination))
            self.destination_selector.add_destination(destination)
        # and make sure there is a watcher
        if self.destwatcher:
            if getconf('watcher_enabled'):
                qDebug("Starting watcher for {!r}".format(destination))
                self.destwatcher.start_watcher(destination)
        return c
    def find_conversation(self, destination):
        # find the conversation for a message destination
        if not self.is_dummy_page():
            return next((self.widget(i) for i in range(self.count()) if self.tabText(i).lower() == destination.lower()),None)
    def select_conversation(self, destination):
        c = self.find_conversation(destination)
        if c:
            # print("Setting current conversation for {} = {!r}".format(destination, c), file=sys.stderr)
            self.setCurrentWidget(c)
            # also clear unread marker
            if self.messages_unread_for_dest(destination):
                qDebug("Clearing unread marker for {}".format(destination))
                self.set_messages_unread_for_dest(destination, False)
                self.destwatcher.update_dest_icon(destination)
            else:
                qDebug("No unread msgs for conversation {}".format(destination))
        else:
            qDebug("select_conversation: can't find conversation for {}".format(destination))
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
                if self.count() == 0:
                    self.add_dummy_page()
            else:
                qDebug("remove_conversation: Can't find index of conversation {!r} ({})".format(c, destination))
        else:
            qDebug("remove_conversation: Can't find conversation with {}".format(destination))
        # and make sure the watcher is removed
        if self.destwatcher:
            self.destwatcher.remove_watcher(destination)
    def remove_all_conversations(self):
        # first clear the conversations
        if not self.is_dummy_page():
            for i in range(self.count()):
                qDebug("Clearing conversation with {!r}".format(self.tabText(i)))
                self.widget(i).clear_conversation()
        # then remove all tabs
        self.clear()
        self.add_dummy_page()
        
    def save_conversations(self):
        if not self.is_dummy_page():
            for i in range(self.count()):
                self.widget(i).save_conversation(i)
        

    # @@@@ have this in a right-click menu for the Tab? Can we have right-click menus?
    def close_conversation(self, idx):
        c = self.widget(idx)
        # print("close_conversation: clearing conversation {} ({!r})".format(idx, c), file=sys.stderr)
        c.clear_conversation()
        d = self.tabText(idx)
        # print("close_conversation: removing destination {!r}".format(d), file=sys.stderr)
        self.destination_selector.remove_destination(d)
        # print("close_conversation: removing tab {}".format(idx), file=sys.stderr)
        self.removeTab(idx)
        if self.count() == 0:
            self.add_dummy_page()
        # and remove the watcher
        if self.destwatcher:
            self.destwatcher.remove_watcher(d)

    # @@@@ have this in a right-click menu for the Tab? Can we have right-click menus?
    def clear_conversation(self, destination):
        c = self.find_conversation(destination)
        if c:
            if verbose:
                qInfo("Clearing conversation with {!r}".format(destination))
            c.clear_conversation()
    def clear_all_conversations(self):
        if not self.is_dummy_page():
            for i in range(self.count()):
                if verbose:
                    qInfo("Clearing conversation with {!r}".format(self.tabText(i)))
                self.widget(i).clear_conversation()

class ConversationTab(AutoBottomScrollArea):
    def __init__(self, parent = None):
        super().__init__()
        self.prev_msg_datetime = None
        self.last_other = None

        # This holds one conversation in a vertically scrolling container, contains the widgets, set as the centralWidget
        self.widget = QWidget() # widget that contains the collection of Vertical Box
        self.msglayout = QVBoxLayout()  # the vertical box that contains the MessageDisplayBoxes
        self.widget.setLayout(self.msglayout)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setWidgetResizable(True)
        # You must add the layout of widget before you call this function; if you add it later, the widget will not be visible
        self.setWidget(self.widget)
        self.init_message_history()

    def add_message(self, other, date, diffhours, text, is_from_net=True):
        if verbose:
            qInfo("Adding message to conversation with {}: {!r}".format(other,text))
        # If self.prev_msg_time is a different day than today, add a line with today's date
        if date is None:
            date = datetime.now()
        # Adjust date to local timezone
        aslocal = date.astimezone()
        if self.prev_msg_datetime is None or aslocal.date() != self.prev_msg_datetime.date():
            self.msglayout.addWidget(self.make_date_marker(aslocal))
            self.prev_msg_datetime = aslocal
        corr = self.make_correspondent_line(other, date, diffhours)
        # Subclass MessageDisplayBox for left/right position, just to easily style them
        if is_from_net:
            box = MessageDisplayBoxLeft()
            contents = [box, corr]
        else:
            box = MessageDisplayBoxRight()
            contents = [corr, box]
        box.setText(text)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        align = Qt.AlignmentFlag.AlignRight if isinstance(box,MessageDisplayBoxRight) else Qt.AlignmentFlag.AlignLeft
        for c in contents:
            row.addWidget(c, alignment=align)
        w = QWidget()
        w.setLayout(row)
        self.msglayout.addWidget(w, alignment=align)

    # def save_conversation(self):
    #     # Traverse msglayout, find the MessageDisplayBoxes, get their text and correspondent/date boxes
    #     # @@@@ This will be too messy. Save the conversations as messages arrive/are sent, instead.
    #     pass

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

    def make_date_marker(self, date):
        dbox = QHBoxLayout()
        dbox.setContentsMargins(0, 0, 0, 0)
        dbox.addWidget(self.makeline(), alignment=Qt.AlignmentFlag.AlignRight)
        d = QLabel(date.strftime("%e %b %Y"))
        d.setScaledContents(True)
        dbox.addWidget(d, alignment=Qt.AlignmentFlag.AlignCenter)
        dbox.addWidget(self.makeline(), alignment=Qt.AlignmentFlag.AlignLeft)
        dw = QWidget()
        dw.setLayout(dbox)
        # @@@@ consider QSS?
        # @@@@ subclass a QWidget and set the style for it instead
        if getconf("date_color"):
            dw.setStyleSheet('background-color: {};'.format(getconf('date_color')))
        return dw

    def make_correspondent_line(self, other, date, diffhours, time=None):
        # Need to translate date to localtime for diffh to be useful.
        nd = date.astimezone()
        if self.last_other is None or other.lower() != self.last_other.lower():
            # New other end, show it together with the time
            tbox = QVBoxLayout()
            tbox.setContentsMargins(0, 0, 0, 0)
            tbox.setSpacing(0)
            tbox.addWidget(QLabel(nd.strftime('%H:%M:%S')+(" ({:+d}h)".format(diffhours) if diffhours != 0 else "")))
            tbox.addWidget(QLabel(other))
            time = QWidget()
            time.setLayout(tbox)
            self.last_other = other
        else:
            time = QLabel(nd.strftime('%H:%M:%S')+(" ({:+d}h)".format(diffhours) if diffhours != 0 else ""))
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

    def canonicalize_dest(self, txt):
        # Try to prettify/canonicalize host part
        u,h = txt.split('@', maxsplit=1)
        destaddr = dns_addr_of_name_search(h, searchlist=getconf('dns_search_list'))
        if destaddr and len(destaddr) > 0:
            desthost = dns_name_of_address(destaddr[0])
            if desthost != h:
                qDebug("Canonicalized dest {!r} to {}@{}".format(txt, u, desthost))
                return "{}@{}".format(u,desthost)
        return txt

    def current_destination_changed(self, newidx):
        if newidx < 0:          # no selection?
            return
        qDebug("current_destination_changed: {} {!r}".format(newidx,self.itemText(newidx)))
        txt = self.itemText(newidx).strip()
        if "@" in txt:
            canonical = self.canonicalize_dest(txt)
            if txt != canonical:
                self.setItemText(newidx,canonical)
        else:
            if verbose:
                qInfo("Bad itemtext {!r}, ignoring".format(txt))
            return
        qDebug("Saving destination index {}".format(newidx))
        settings.setValue('destination_list_index', newidx)
        if self.tabbar:
            # Keep destination_list in sync with tab selection
            dest = self.itemText(newidx)
            if debug:
                qDebug("current_destination_changed: itemtext is {!r}".format(dest))
            if self.currentIndex() != newidx:
                # print("current_destination_changed: new index {} not current ({}), changing it".format(newidx, self.currentIndex()), file=sys.stderr)
                self.setCurrentIndex(newidx)
            c = self.tabbar.find_conversation(dest)
            if c:
                i = self.tabbar.indexOf(c)
                # print("Current dest changed: setting tabbar index {}".format(i), file=sys.stderr)
                self.tabbar.setCurrentIndex(i)
            else:
                # print("current_destination_changed: can't find conversation with {}".format(dest), file=sys.stderr)
                if verbose:
                    qInfo("Destination changed to {!r}, adding a conversation for it".format(dest))
                if getconf('restore_conversation_tabs'):
                    self.tabbar.add_conversation(dest)
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
            settings.setValue('destination_list',[self.itemText(i) for i in range(self.count())])
            if getconf('restore_conversation_tabs'):
                self.tabbar.add_conversation(dest)
        else:
            # print("Not adding destination {!r}: already exists".format(dest), file=sys.stderr)
            pass
    def remove_destination(self, dest):
        i = self.find_destination(dest)
        if i >= 0:
            c = self.tabbar.find_conversation(dest)
            if c and c.msglayout.count() > 2:
                # if it has no messages (more than header and spacer), ask for confirmation
                qDebug("remove_destination: have conversation, count {} {!r}".format(
                    c.msglayout.count(), [c.msglayout.itemAt(i) for i in range(c.msglayout.count())]))
                r = QMessageBox.question(self, "Conversation exists",
                                         "Conversation messages for destination {} exists. Do you want to remove the messages and conversation too?".format(dest))
                if r == QMessageBox.StandardButton.No:
                    if verbose:
                        qInfo("Cancelled removing destination {}".format(dest))
                    QMessageBox.information(self,"Keeping destination",
                                            "Keeping destination {}".format(dest))
                    return
            if c:
                self.tabbar.remove_conversation(dest)
            if verbose:
                qInfo("Removing destination {} ({}) from destination list".format(i, dest))
            self.removeItem(i)
            settings.setValue('destination_list',[self.itemText(i) for i in range(self.count())])
            settings.setValue('destination_list_index',self.currentIndex())

    def select_destination(self, dest):
        di = self.find_destination(dest)
        if di >= 0:
            self.setCurrentIndex(di)
            qDebug("select_destination: Saving destination index {}".format(di))
            settings.setValue('destination_list_index', di)
        else:
            # print("Can't select destination {!r}: not found".format(dest), file=sys.stderr)
            pass
    def edit_destination_list(self):
        curr_dest = self.currentText() # save current, to re-select it below
        # make sure all active conversations are in the dest list. 
        if not self.tabbar.is_dummy_page():
            dlist = [self.itemText(i) for i in range(self.count())]
            active = [self.tabbar.tabText(i) for i in range(self.tabbar.count()) if self.tabbar.widget(i).msglayout.count() > 2]
        else:
            dlist = []
            active = []
        qDebug("active conversations {!r}".format(active))
        while True:
            input,ok = QInputDialog.getMultiLineText(self,"Edit destination menu","user@host (one per line)",
                                         text="\n".join(dlist))
            if ok and input and len(input.strip()) > 0:
                # Canonicalize/expand host names
                new_dlist = [self.canonicalize_dest(d.strip()) for d in input.strip().split("\n")]
                # @@@@ also remove duplicates after expansion
                if debug:
                    qInfo("Old dlist: {!r}".format(dlist))
                    qInfo("New dlist: {!r}".format(new_dlist))
                badd = next((d for d in new_dlist if not re.match(r"^[\w_.-]+@[\w_.-]+$",d)),None)
                if badd:
                    response = QMessageBox.warning(self,"Syntax error","<b>Syntax error<:/b> Destination should be user@host: "+badd,
                                                   buttons=QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Cancel)
                    if response == QMessageBox.StandardButton.Cancel:
                        qDebug("Cancelled editing destination list")
                        return
                else:
                    missing = [d for d in active if d not in new_dlist]
                    if len(missing) > 0:
                        QMessageBox.information(self,"Keeping active destinations",
                                                "Keeping destinations of active conversations: {}".format(", ".join(missing)))
                        new_dlist += missing # @@@@ should keep order of dlist
                    qDebug("Setting destination list: {!r}".format(new_dlist))
                    self.clear()
                    self.insertItems(0,new_dlist)
                    settings.setValue('destination_list',new_dlist)
                    # And update Conversation tabs to match new_dlist (always when changing destination_list
                    if getconf('restore_conversation_tabs'):
                        for d in new_dlist:
                            c = self.tabbar.find_conversation(d)
                            if c is None:
                                qDebug("Adding conversation for {!r}".format(d))
                                self.tabbar.add_conversation(d)
                            else:
                                qDebug("Already have conversation for {!r}: {!r}".format(d, c))
                    # also remove conversation tabs AFTER adding any new ones, to avoid stopping watcher
                    if debug:
                        qInfo("removing dlist: {!r}".format([removed for removed in dlist if removed not in new_dlist]))
                    for d in [removed for removed in dlist if removed not in new_dlist]:
                        qDebug("removing conversation {!r}".format(d))
                        self.tabbar.remove_conversation(d)
                    # finally restore selected destination
                    if curr_dest in new_dlist:
                        self.select_destination(curr_dest)
                    return
            else:
                qDebug("Cancelled editing destination list")
                return
    def clear_destination_list(self):
        # disallow this unless conversations are empty @@@@ unless some setting? @@@@ make the user confirm
        if self.tabbar.is_dummy_page():
            active = []
        else:
            active = [self.tabbar.tabText(i) for i in range(self.tabbar.count()) if self.tabbar.widget(i).msglayout.count() > 2]
        if len(active) > 0:
            # @@@@ Make the user confirm
            QMessageBox.information(self,"Keeping active destinations",
                                    "Keeping destinations of active conversations: {}".format(", ".join(active)))
            dlist = [self.itemText(i) for i in range(self.count())]
            for d in [dest for dest in dlist if dest not in active]:
                self.remove_destination(d)
        else:
            # also remove conversation tabs
            self.tabbar.remove_all_conversations()
            self.clear()
            settings.setValue('destination_list',[])
            settings.setValue('destination_list_index',0)

# subclass of ChaosUserWatcher with a new got_result which does the following:
# - keep track of previous state of host, and each of the reported users (destinations)
# -- state of host is up or down
# -- state of user is not-logged-in, idle low/medium/high (<30m, <2h, otherwise; configurable limits)
# - If user state changes, change icon appropriately (three colors, configurable) - and notification?
# - If user is not-logged-in, change icon based on host (up: color, down: no color)
# Also redefine watcher_error to analyse error and perhaps pop up a message (e.g. ChaosSocketError).
class ConverseDestWatcher(ChaosUserWatcher):

    debugp = False
    paused = False
    host_states = NocaseDict()        # host -> host_up_p
    dest_states = NocaseDict()        # user@host -> idle-class
    class IdleLevel(StrEnum):
        ACTIVE = auto()
        IDLE = auto()
        AWAY = auto()

    tabbar = None               # need a handle on the tab bar in order to update icons
    host_icon_list = dict()     # dict host_up_p -> icon
    idle_icon_list = dict()     # dict IdleLevel -> icon

    def __init__(self):
        super().__init__()
        self.initialize_icons()
        self.debugp = debug

    # Call this when icon color config changes
    def initialize_icons(self):
        self.host_icon_list[False] = QIcon() # no icon at all
        self.host_icon_list[True] = self.make_icon(getconf('host_up_color'))
        self.idle_icon_list[self.IdleLevel.ACTIVE] = self.make_icon(getconf('active_icon_color'))
        self.idle_icon_list[self.IdleLevel.IDLE] = self.make_icon(getconf('idle_icon_color'))
        self.idle_icon_list[self.IdleLevel.AWAY] = self.make_icon(getconf('away_icon_color'))

    def make_icon(self, colorspec):
        pm = QPixmap(12,12)
        pm.fill(QColor(colorspec))
        return QIcon(pm)

    def set_tabbar(self, tb):
        self.tabbar = tb

    def idle_level(self, idle):
        return self.IdleLevel.ACTIVE if idle < getconf('idle_limit') else self.IdleLevel.IDLE if idle < getconf('away_limit') else self.IdleLevel.AWAY

    # To be used after changing idle/away limits
    def refresh_idle_levels(self):
        for d in self.dest_states.keys():
            lev, idle = self.dest_states[d]
            self.dest_states[d] = (self.idle_level(idle), idle)

    def set_icon_for_dest(self, dest, icon, tooltip):
        if self.tabbar:
            c = self.tabbar.find_conversation(dest)
            if c:
                self.tabbar.set_conversation_tooltip(c, tooltip)
                if not self.tabbar.messages_unread_for_dest(dest):
                    if self.debugp:
                        qDebug("set_icon_for_dest: setting new icon for {} ({})".format(dest,tooltip))
                    self.tabbar.set_conversation_icon(c, icon)
                elif self.debugp:
                    qDebug("set_icon_for_dest: NOT changing Unread marker icon for {}".format(dest))
            elif self.debugp:
                qDebug("set_icon_for_dest: Can't find conversation {!r}".format(dest))
        elif self.debugp:
            qDebug("set_icon_for_dest: no tabbar!")

    # Clear icons when watcher goes away
    def end_watcher(self, host):
        _, users = self.workers[host]
        for u in users:
            self.set_icon_for_dest("{}@{}".format(u,host), QIcon(), None)
        super().end_watcher(host)
    def remove_watcher(self, userathost):
        self.set_icon_for_dest(userathost, QIcon(), None)
        super().remove_watcher(userathost)

    # E.g. when a message arrives from a dest, check their idleness
    def refresh_status_for_dest(self, dest):
        u,h = dest.split("@", maxsplit=1)
        self.refresh_watcher(h)
    def get_status_for_dest(self, dest):
        if dest in self.dest_states:
            return self.dest_states[dest][0]
        u,h = dest.split("@", maxsplit=1)
        if h in self.host_states:
            return self.host_states[h]
        return None

    def clear_state(self):
        for h in self.workers:
            if h in self.host_states:
                del self.host_states[h]
            w,us = self.workers[h]
            for u in us:
                d = "{}@{}".format(u,h)
                # also clear all icons while paused
                self.set_icon_for_dest(d, QIcon(), None)
                if d in self.dest_states:
                    del self.dest_states[d]
    def pause(self):
        self.pause_watchers()
        self.paused = True
        # clear state
        self.clear_state()

    def unpause(self):
        self.paused = False
        # Don't do this: self.unpause_watchers()
        # because destinations may have appeared while we weren't watching
        for h in self.workers:
            w, us = self.workers[h]
            for u in us:
                self.start_watcher("{}@{}".format(u,h), interval=w.default_interval())
        # re-set all icons - go through tabbar to let it check for unread messages
        self.tabbar.update_all_icons()

    def update_host_icon(self, host, user=None):
        _,watched = self.workers[host]
        # qDebug("host states: {!r}".format(self.host_states))
        if host in self.host_states:
            host_up_p = self.host_states[host]
            for u in watched:
                if user is None or u == user.lower(): # Unless we're given a specific user who doesn't match
                    d = "{}@{}".format(u,host)
                    if self.debugp:
                        qDebug("setting icon for {}, host is {}".format(d,"up" if host_up_p else "down"))
                    self.set_icon_for_dest(d, self.host_icon_list[host_up_p], 
                                           "Host is {}".format("up (user not online)" if host_up_p else "down"))
                elif self.debugp:
                    qDebug("update_host_icon: NOT updating icon for user {} given user {}".format(u,user))
    def update_dest_icon(self, dest):
        u,h = dest.split("@",maxsplit=1)
        if self.debugp:
            qInfo("dest {} states: {!r}".format(dest, self.dest_states))
        if dest in self.dest_states: # if there is state for this user
            ilevel = self.dest_states[dest][0]
            if self.debugp:
                qDebug("setting icon for {}, idle level is {}".format(dest,ilevel))
            self.set_icon_for_dest(dest, self.idle_icon_list[ilevel],
                                   "User is {}".format(ilevel))
        elif h in self.host_states:
            self.update_host_icon(h, u) # if there is state at least for the host
        elif not getconf('watcher_enabled'):
            self.set_icon_for_dest(dest, QIcon(), None) # if watching is disabled

    # New handler for results
    def got_result(self, result):
        # Handler for result signal: (host, host_up_p, users=[(user,idle)*])
        try:
            host, host_up_p, users = result
        except ValueError:
            qDebug("Unexpected result from dest watcher: {!r}".format(result))
            return
        # host = host.lower()
        if self.debugp:
            qDebug("got_result: host {!r} up-p {!r} users {!r}".format(host,host_up_p,users))
        if self.paused:
            if debug:
                qInfo("got_result: watching is paused, ignoring result")
            return
        # Update icon based on up-p if it changed
        if host not in self.host_states or self.host_states[host] != host_up_p:
            # @@@@ Do something more meaningful here, like notification
            if verbose:
                qInfo("{}: Host {} is now {}".format(datetime.now().strftime("%d-%b-%Y %T"), host, "up" if host_up_p else "down"))
            self.host_states[host] = host_up_p
            # update icon for all destinations matching host
            self.update_host_icon(host)
        # Check for users no longer logged in for this host
        for d in self.dest_states.keys():
            u,h = d.lower().split("@",maxsplit=1)
            if self.debugp:
                qDebug("checking old state for {}".format(d))
            if h == host.lower() and u not in map(lambda x: x[0].lower(),users):
                # No longer logged in, set the host-based icon
                if self.debugp:
                    qDebug("{} is not in {!r}, resetting icon".format(d, users))
                # set tooltip describing status
                self.set_icon_for_dest(d, self.host_icon_list[self.host_states[h]],
                                       "Host is {} (user not online)".format("up" if self.host_states[h] else "down"))
            elif h == host.lower():
                if self.debugp:
                    qDebug("{} is in {!r}, not resetting icon".format(d, users))
        # Check the idleness of logged-in users
        watched = self.watched_users(host)
        if self.debugp:
            qDebug("Watched users for host {} is {!r}".format(host, watched))
        for user,idle in users:
            if user.lower() in watched:
                dest = "{}@{}".format(user,host).lower()
                ilevel = self.idle_level(idle)
                if dest not in self.dest_states or self.dest_states[dest][0] != ilevel:
                    if verbose:
                        qInfo("{}: {} is now {}".format(datetime.now().strftime("%d-%b-%Y %T"), dest, ilevel))
                    self.dest_states[dest] = (ilevel, idle)
                    # update icon (also updates tooltip)
                    self.update_dest_icon(dest)
            elif verbose or self.debugp:
                qDebug("Got result for {} at {} but not being watched".format(user,host))

    # New handler for errors
    def watcher_error(self, data):
        try:
            etype, exc, trace_string = data
        except ValueError:
            pass                # didnt get the triple we're expecting
        else:
            # For ChaosSocketErrors, remove all icons and state, to avoid misleading info
            if etype == ChaosSocketError:
                self.clear_state()
            if main_window.error_pane:
                # Temporarily show the error message
                main_window.error_pane.showMessage("{}".format(exc), 10*1000)
                main_window.error_pane.setVisible(True)

# Saving/restoring messages:
# - Save messages chronologically on disk, in the 'conversation_save_file' configured.
# Format:
# - first line is destination: for incoming msgs this should be "your userid", for outgoing msgs "to:destuser@host"
# - second line is in SEND protocol format, but with the (original) date in standardized format
#   (dd-mmm-yyyy h:m:s) and for incoming messages, including a (calculated) timezone +-HHMM
# - the rest is the text of the message.
# Messages are separated (ended) by a line with only ^L (for historical reasons).

class MessageStorage:
    debugp = False
    uname = None

    def __init__(self,mw):
        from getpass import getuser
        self.uname = getuser()
        self.main_window = mw
        if getconf('conversation_save_file') is None or len(getconf('conversation_save_file')) == 0:
            # default to a file in the user's home directory
            home = QStandardPaths.locate(QStandardPaths.StandardLocation.HomeLocation, "", QStandardPaths.LocateOption.LocateDirectory)
            qDebug("home: {!r}".format(home))
            qDebug("default conversation_save_file: {!r}".format(getconf('default_conversation_save_file')))
            fn = os.path.join(home, getconf('default_conversation_save_file'))
            qDebug("Initializing conversation_save_file to {!r}".format(fn))
            settings.setValue('conversation_save_file', fn)
        self.init_conversation_save_file()

    def init_conversation_save_file(self):
        fn = getconf('conversation_save_file')
        exists = os.path.isfile(fn)
        qDebug("conversation_save_file {!r} {}{}".format(
            fn, "exists" if exists else "does NOT exist", ", size {}".format(os.path.getsize(fn) if exists else "")))
        if getconf('save_restore_messages_enabled') and not exists:
            try:
                # create it
                qDebug("Creating {!r}".format(fn))
                with open(fn, "w") as f:
                    pass
                # so we can set decent protection on it
                qDebug("Setting modes for {!r}".format(fn))
                import stat
                os.chmod(fn, stat.S_IRUSR | stat.S_IWUSR)
            except OSError as m:
                qInfo("Error creating {!r}: {}".format(fn, m))

    def save_message(self, dest, msg):
        # Append the message to the conversation_save_file
        try:
            if dest is None:    # for me
                from getpass import getuser
                dest = getuser()
                qDebug("saving msg to None: using my name {!r}".format(dest))
            elif not dest.startswith("to:"):
                qInfo('save_message: dest should be None or "to:dest": {!r}'.format(dest))
            with open(getconf('conversation_save_file'), "a") as f:
                # RFC arg (me), or "to:remotedest"
                print(dest, file=f)
                print(msg, file=f)  # the raw message including header/first line
                print("\f", file=f) # separate messages by FF
        except OSError as m:
            qInfo("Failed to save message: {}".format(m))

    def read_message(self, f):
        # Read a message (to the next FF) from the file, return firstline (dest) and rest (msg).
        # Returns None,None for EOF.
        # @@@@ There must be better, cuter, more portable ways, in particular removing newlines.
        first = f.readline().rstrip("\r\n")
        if len(first) == 0:
            return None,None    # eof
        lines = []
        for line in f:
            line = line.rstrip("\r\n") # need to avoid stripping \f
            if line == "\f":
                break
            lines.append(line)
        return first,"\n".join(lines)

    def restore_messages(self):
        # Restore messages from the conversation_save_file, adding them to conversations.
        n = 0
        savefile = getconf('conversation_save_file')
        try:
            self.main_window.disable_unread_markers()
            with open(savefile, "r") as f:
                while True:
                    destuser, msg = self.read_message(f)
                    qDebug("read message for {!r}: len {}".format(destuser,msg if msg is None else len(msg)))
                    if destuser is None or msg is None:
                        break   # assume EOF/done
                    n = n+1
                    _,uname,host,date,diffh,text = parse_send_message(msg, destuser=destuser, searchlist=getconf('dns_search_list'))
                    self.main_window.add_message(uname, host, date, diffh, text, is_from_net=not destuser.startswith("to:"))
            # Clear all "unread" markers.
            self.main_window.clear_all_unread_markers()
        except EOFError:
            pass                # we're done
        except OSError as m:
            qInfo("Failed to restore messages: {}".format(m))
        finally:
            self.main_window.enable_unread_markers()
        # @@@@ Put this also in status field
        qInfo("Restored {} messages from {!r}, {} bytes".format(n, savefile, os.path.getsize(savefile)))

    def clear_messages(self):
        try:
            with open(getconf('conversation_save_file'), "w") as f:
                pass
        except OSError as m:
            qInfo("Failed to clear messages: {}".format(m))

class MessageReceiver:
    debugp = False
    conn = None
    closing_down = False

    def __init__(self, main_window):
        from PyQt6.QtCore import QThreadPool
        self.threadpool = QThreadPool()
        self.set_debug(debug)
        from getpass import getuser
        self.myuser = getuser().lower()
        self.main_window = main_window

    def set_debug(self, debug):
        self.debugp = debug

    def start_receiver(self):
        w = PersistentWorker(self.receiver_receive_message, interval = 0) # keep going without waiting
        w.set_debug(debug)
        w.signals.error.connect(self.receiver_error)
        w.signals.result.connect(self.receiver_message_received)
        w.signals.finished.connect(self.receiver_finished)
        if self.debugp:
            w.signals.progress.connect(self.receiver_progress)
        self.receiver = w
        if self.debugp:
            qDebug("Starting receiver")
        self.threadpool.start(w)
    def stop_receiver(self, wait_time=10):
        if self.debugp:
            qDebug("Stopping receiver")
        self.closing_down = True # ignore errors
        self.conn.abort()        # @@@@ aaargh - but it helps
        self.receiver.signals.please_stop.emit(666)
        done = self.threadpool.waitForDone((wait_time)*1000)
        if self.debugp:
            qDebug("Receiver thread finished: {}".format(done))
    def pause_receiver(self):
        if self.debugp:
            qDebug("Pausing receiver")
        self.receiver.set_interval(0x7fffff)
    def unpause_receiver(self):
        if self.debugp:
            qDebug("Unpausing receiver")
        self.receiver.set_default_interval()

    # This runs in the receiver thread
    def receiver_receive_message(self, progress_callback, interval=None):
        # Note: errors are handled through receiver_error
        try:
            from chaosnet import PacketConn
            self.conn = PacketConn() # get a handle on the conn for get_send_message
            vals = get_send_message(searchlist=getconf('dns_search_list'), conn=self.conn)
        except ChaosSocketError as m:
            # print("DEBUG: socket error {}".format(m), file=sys.stderr)
            progress_callback.emit((None, "{}".format(m)))
            time.sleep(5)       # wait before trying again
            return
        if vals is None:
            progress_callback.emit((vals,"No message received by get_send_message!")) # perhaps for some other user
            return
        destuser,uname,host,date,diffh,text = vals
        if destuser is None:
            progress_callback.emit((destuser,"Message for no user received?")) # Invalid request
            return
        # Filter out the silly header line that ITS QSEND puts there.
        # Also filter TOPS-20 headers (Date: and From:)
        # @@@@ perhaps check the matches against destuser/myhost?
        hi = get_dns_host_info(host)
        if hi and 'os' in hi and hi['os'].lower() == "its":
            # ITS adds a To: header
            m = re.match(r"To: ([\w_.]+) at ([\w.]+)", text)
            if m:
                progress_callback.emit(("ITS To: header being removed",m.group(0)))
                text = text[m.end():].lstrip()
        if hi and 'os' in hi and hi['os'].lower() == "tops-20":
            # TOPS-20 adds Date: and From: headers
            m = re.match(r"Date: .+", text)
            if m:
                progress_callback.emit(("TOPS-20 Date: header being removed", m.group(0)))
                text = text[m.end():].lstrip()
            m = re.match(r"From: ([\w_.]+)@([\w_.]+)", text)
            if m:
                # @@@@ perhaps check against uname and host
                progress_callback.emit(("TOPS-20 From: header being removed",m.group(0)))
                text = text[m.end():].lstrip()
        if destuser.lower() == self.myuser:
            return (uname,host,date,diffh,text)
        else:
            progress_callback.emit(("Message for other user slipped through",destuser))


    # These run in the "main thread"
    def receiver_finished(self, val):
        if verbose:
            qInfo("Receiver finished: {!r}".format(val))
    def receiver_progress(self, val):
        if verbose:
            qInfo("Receiver: {!r}".format(val))
    def receiver_error(self,data):
        try:
            etype, exc, trace_string = data
        except ValueError:
            pass                # didnt get the triple we're expecting
        else:
            if etype == ChaosSocketError:
                qInfo("Error in receiver: {}".format(exc))
                return
            qInfo("Error in receiver: {}".format(exc))
            if not self.closing_down:
                raise exc
    def receiver_message_received(self, data):
        if data is None:
            qDebug("No message received?!")
            return
        uname, host, date, diffhours, text = data
        if self.debugp:
            qDebug("Message received from {!r} at {!r}".format(uname,host))
        self.main_window.add_message(uname, host, date, diffhours, text, True)
        if getconf('save_restore_messages_enabled'):
            self.main_window.message_store.save_message(None, make_send_message(text, uname=uname, hostname=host, date=date))
        beep('message_incoming')

class ScreenLockWatcher:
    screen_is_now_locked = False
    screen_lock_watcher = None
    debugp = False

    def __init__(self, destwatcher):
        from PyQt6.QtCore import QThreadPool
        self.screen_is_now_locked = screen_is_locked()
        self.threadpool = QThreadPool()
        self.destwatcher = destwatcher
        # self.set_debug(debug)

    def set_debug(self, debug):
        self.debugp = debug

    def start_screen_lock_watcher(self):
        w = PersistentWorker(self.screen_locked_wrapper, interval=10 if debug else 0.5)
        w.set_debug(self.debugp)
        w.signals.result.connect(self.screen_locked_status)
        w.signals.finished.connect(self.screen_locked_finished)
        if self.debugp:
            w.signals.progress.connect(self.screen_locked_progress)
        w.signals.error.connect(self.screen_locked_error)
        self.screen_lock_watcher = w
        if self.debugp:
            qDebug("Starting screen lock watcher")
        self.threadpool.start(w)

    def stop_screen_lock_watcher(self, wait_time=10):
        self.screen_lock_watcher.signals.please_stop.emit(666)
        done = self.threadpool.waitForDone((wait_time)*1000)
        if self.debugp:
            qDebug("Screen lock watcher thread finished: {}".format(done))

    def screen_locked_wrapper(self, progress_callback, interval=None):
        v = screen_is_locked()
        progress_callback.emit((v,"screen is {}".format("locked" if v else "NOT locked")))
        return v
    def screen_locked_status(self, status):
        if self.debugp:
            qDebug("screen_locked_status: {!r}".format(status))
        if status != self.screen_is_now_locked:
            self.screen_is_now_locked = status
            if status:
                if verbose:
                    qInfo("{}: screen is now locked, pausing watchers".format(datetime.now().strftime("%d-%b-%Y %T")))
                self.destwatcher.pause()
            else:
                if verbose:
                    qInfo("{}: screen is now UNlocked, unpausing watchers".format(datetime.now().strftime("%d-%b-%Y %T")))
                self.destwatcher.unpause()
        else:
            if self.debugp:
                qDebug("No change in locked status")
    def screen_locked_finished(self, val):
        if verbose:
            qInfo("Screen lock watcher finished: {!r}".format(val))
    def screen_locked_progress(self, val):
        if verbose:
            qInfo("Screen lock watcher: {!r}".format(val))
    def screen_locked_error(self,data):
        try:
            etype, exc, trace_string = data
        except ValueError:
            pass                # didnt get the triple we're expecting
        else:
            qInfo("Error in screen lock watcher: {}".format(exc))
            raise exc

class MainWindow(QMainWindow):

    def aboutme(self):
        QMessageBox.about(self, "About "+app.applicationName(), 
                          "<center><b>"+app.applicationName()+" "+app.applicationVersion()+"</b></center><br>"+
                          app.applicationName()+" is a program to have conversations on Chaosnet.<br>"+
                          # "Please see https://"+app.organizationDomain()+".<br>"+
                          "Copyright © 2025-2026 Björn Victor (bjorn@victor.se)")

    def set_message_timeout(self):
        input,ok = QInputDialog.getInt(self,"Set send timeout","Timeout when sending messages (seconds)",
                                       getconf('send_message_timeout'), min=1, max=30, step=1)
        if ok:
            if input != getconf('send_message_timeout'):
                # avoid saving the default_config value
                settings.setValue('send_message_timeout', input)
        else:
            qDebug("Setting message timeout cancelled")
    def set_online_interval(self):
        i = getconf('watcher_interval')
        input,ok = QInputDialog.getInt(self,"Set online interval","Interval for checking if destinations are online (minutes)",
                                       getconf('watcher_interval'), min=5, max=30, step=1)
        if ok:
            if input != getconf('watcher_interval'):
                # avoid saving the default_config value
                settings.setValue('watcher_interval', input)
                # also update the running watchers
                self.destwatcher.set_interval(input)
        else:
            qDebug("Setting online interval cancelled")

    def set_idle_limit(self):
        input,ok = QInputDialog.getInt(self,"Set idle limit","Lower limit for when a user is seen as idle (minutes)",
                                       getconf('idle_limit'), min=5, max=getconf('away_limit'), step=1)
        if ok:
            if input != getconf('idle_limit'):
                # avoid saving the default_config value
                settings.setValue('idle_limit', input)
                # update levels
                self.destwatcher.refresh_idle_levels()
                # refresh icons
                self.tbar.update_all_icons()
        else:
            qDebug("Setting idle limit cancelled")
    def set_away_limit(self):
        input,ok = QInputDialog.getInt(self,"Set away limit","Lower limit for when a user is seen as away (minutes)",
                                       getconf('away_limit'), min=getconf('idle_limit'), max=240, step=10)
        if ok:
            if input != getconf('away_limit'):
                # avoid saving the default_config value
                settings.setValue('away_limit', input)
                # update levels
                self.destwatcher.refresh_idle_levels()
                # refresh icons
                self.tbar.update_all_icons()
        else:
            qDebug("Setting away limit cancelled")

    def set_multi_line_message_lines(self, lines=None):
        input,ok = QInputDialog.getInt(self,"Number of lines","Number of lines in input window",
                                       getconf('multi_line_message_lines'), min=1, max=10, step=1)
        if ok:
            if input != getconf('multi_line_message_lines'):
                # avoid saving the default_config value
                settings.setValue('multi_line_message_lines', input)
                # change the height of self.input
                if isinstance(self.input, MessageInputMultiLine):
                    self.input.setup_height(input)
        else:
            qDebug("Setting multi-line input lines cancelled")

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
                qDebug("Setting DNS server: {!r}".format(s))
                if set_dns_resolver_address(s) is None:
                    # can fail e.g. if the name isn't actually in DNS
                    r = QMessageBox.warning(self,"Error","<b>Error:</b> Failed setting DNS server",
                                            buttons=QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.RestoreDefaults)
                else:
                    settings.setValue('dns_server', s)
            else:
                qWarning("Bad syntax for DNS server: {!r}".format(s))
                r = QMessageBox.warning(self,"Syntax error","<b>Syntax error:</b> Domain name syntax error",
                                        buttons=QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.RestoreDefaults)
            if r == QMessageBox.StandardButton.RestoreDefaults:
                qDebug("Restoring DNS server default: {!r}".format(default_config['dns_server']))
                # Clear the settings value, so the default_config is used instead
                settings.setValue('dns_server',None)
                if set_dns_resolver_address(default_config['dns_server']) is None:
                    QMessageBox.critical(self,"Error","<b>Error:</b> Failed setting default DNS server!")
        else:
            qDebug("Setting DNS server cancelled")

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
                    response = QMessageBox.warning(self,"Syntax error","<b>Syntax error:</b> Domain name syntax error: "+badd,
                                                   buttons=QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Cancel)
                    if response == QMessageBox.StandardButton.Cancel:
                        qDebug("Cancelled DNS search list setting")
                        return
                else:
                    qDebug("Setting DNS search list: {!r}".format(dlist))
                    settings.setValue('dns_search_list',dlist)
                    return
            else:
                qDebug("Cancelled DNS search list setting")
                return

    def make_icon(self, colorspec):
        # @@@@ make the icon have a thin border to make it stand out in the menu
        # @@@@ cf QPainter.fillRect, QRect
        pm = QPixmap(12,12)
        pm.fill(QColor(colorspec))
        # qDebug("Made icon from pixmap for color {!r} ({!r}): {!r}".format(colorspec,QColor(colorspec).name(),pm))
        return QIcon(pm)
        
    def edit_background_color(self, cf_name):
        # print("Getting a color setting for {} (default {})".format(cf_name,getconf(cf_name)), file=sys.stderr)
        color = QColorDialog.getColor(QColor(getconf(cf_name)), self)
        if color.isValid() and color.name() != getconf(cf_name):
            qDebug("Got a {} color: {}".format(cf_name,color.name()))
            return color.name()
        else:
            qDebug("No {} color: {!r}".format(cf_name, color.name() if color.isValid() else color))

    def set_background_color(self, color=None):
        c = self.edit_background_color('background_color') if not color else color
        if c:
            settings.setValue('background_color', c)
            self.background_color_action.setIcon(self.make_icon(c))
            app.setStyleSheet(app.styleSheet()+"QMainWindow{"+"background-color: {};".format(c)+"}\n")

    def set_background_color_from_me(self, color=None):
        c = self.edit_background_color('from_me_color') if not color else color
        if c:
            qDebug("Setting from_me_color to {!r}".format(c))
            settings.setValue('from_me_color', c)
            self.from_me_color_action.setIcon(self.make_icon(c))
            self.init_stylesheet()
        else:
            qDebug("No from_me_color selected?")
    def set_background_color_from_net(self, color=None):
        c = self.edit_background_color('from_net_color') if not color else color
        if c:
            qDebug("Setting from_net_color to {!r}".format(c))
            settings.setValue('from_net_color', c)
            self.from_net_color_action.setIcon(self.make_icon(c))
            self.init_stylesheet()
        else:
            qDebug("No from_net_color selected?")

    def reset_background_colors(self):
        qDebug("Resetting background colors")
        self.set_background_color_from_me(default_config['from_me_color'])
        self.set_background_color_from_net(default_config['from_net_color'])
        self.set_background_color(default_config['background_color'])
        for s in ['from_net_color','from_me_color','background_color']:
            settings.remove(s)

    def set_icon_color(self, conf_field, action, color=None):
        c = self.edit_background_color(conf_field) if not color else color
        if c:
            if debug:
                qDebug("Setting icon for {!r} to {!r}".format(action,c))
            settings.setValue(conf_field, c)
            action.setIcon(self.make_icon(c))   # the menu action icon
            self.destwatcher.initialize_icons() # the destination icons
            # also refresh the icons in the dest list
            self.tbar.update_all_icons()
    def set_icon_color_idle(self, color=None):
        self.set_icon_color('idle_icon_color', self.idle_color_action, color)
    def set_icon_color_away(self, color=None):
        self.set_icon_color('away_icon_color', self.away_color_action, color)

    def clear_all_conversations(self):
        self.tbar.clear_all_conversations()
    def remove_all_conversations(self):
        self.tbar.remove_all_conversations()
    def clear_current_conversation(self):
        currdest = self.tbar.tabText(self.tbar.currentIndex())
        if self.tbar.is_dummy_page():
            return
        if currdest and len(currdest) > 0:
            qDebug("Clearing conversation with {}".format(currdest))
            self.tbar.clear_conversation(currdest)
    def remove_current_conversation(self):
        if self.tbar.is_dummy_page():
            return
        currdest = self.tbar.tabText(self.tbar.currentIndex())
        if currdest and len(currdest) > 0:
            qDebug("Removing conversation with {}".format(currdest))
            self.tbar.remove_conversation(currdest)
    def remove_current_destination(self):
        currdest = self.cbox.currentText()
        if currdest and len(currdest) > 0:
            qDebug("Removing destination {}".format(currdest))
            self.cbox.remove_destination(currdest)

    def reset_icon_colors(self):
        for conf, act in self.icon_color_actions.items():
            self.set_icon_color(conf, act, getconf(conf))

    def reset_settings(self, noconfirm=False):
        if not noconfirm:
            r = QMessageBox.question(self, "Reset all settings?", "Reset all settings?")
            if r == QMessageBox.StandardButton.No:
                qDebug("Cancelled resetting settings")
                return
        # Reset settings
        settings.clear()
        # Also update effect of settings: background colors
        self.reset_background_colors()
        # update levels
        self.destwatcher.refresh_idle_levels()
        # also fix watcher icons
        self.reset_icon_colors()
        self.destwatcher.set_interval(getconf('watcher_interval'))
        self.set_destination_checks_enabled(getconf('watcher_enabled')) # this has side effects
        # self.clear_saved_messages()
        # Resize to default
        if getconf('MainWindowSize'):
            self.resize(getconf('MainWindowSize'))
        if getconf('MainWindowPosition'):
            # If there is a default, move there
            self.move(getconf('MainWindowPosition'))
        else:
            # Else find the middle of the screen we're on
            scr = app.screenAt(self.pos())
            sz = scr.size()
            wsz = getconf('MainWindowSize')
            self.move(QPoint(round((sz.width()-wsz.width())/2), round((sz.height()-wsz.height())/2)))

    def sendit(self):
        if len(self.input.toPlainText().strip()) == 0:
            # just noop. This is slightly better than disabling the button, which makes it almost invisible (on macOS).
            return
        if not self.remote_host() or not self.remote_user():
            beep('alert')
            QMessageBox.critical(self,"Error","<b>Error:</b> Destination user/host unknown!",
                                 buttons=QMessageBox.StandardButton.Ok)
            return
        # Expand destination host (sigh, searchlist configuration...)
        # @@@@ cf private networks where names might not be in DNS?
        destaddr = dns_addr_of_name_search(self.remote_host(),searchlist=getconf('dns_search_list'))
        if destaddr is None or len(destaddr) < 1:
            QMessageBox.critical(self,"Error","<b>Error:</b> Destination host {!r} unknown on Chaosnet".format(self.remote_host()),
                                 buttons=QMessageBox.StandardButton.Ok)
            return
        if len(self.input.toPlainText()) > 0:
            # prettify/canonicalize
            canonical = self.cbox.canonicalize_dest(self.cbox.currentText())
            if canonical != self.cbox.currentText():
                qDebug("Setting dest to {!r} (canonical name of {!r})".format(canonical, self.cbox.currentText()))
                self.cbox.setCurrentText(canonical) # this might not be updated yet
            u,h = self.cbox.currentText().split("@",maxsplit=1)
            qDebug("Setting destination {}@{}".format(u,h))
            self.set_destination(u,h, True) # update dest, and switch to it
            # first lock the input, send it, and when it's sent, unlock (in case it takes time)
            if verbose:
                qInfo("Sending to {}@{}: {!r}".format(u,h, self.input.toPlainText()))
            self.input.setReadOnly(True)
            try:
                other = "{}@{}".format(u,h)
                # @@@@ need a cancel button, and a timeout setting
                # @@@@ need to run send_message in a Worker.
                msg = self.input.toPlainText()
                send_message(u,h, msg, timeout=getconf('send_message_timeout'),myhostname=getconf('my_chaos_hostname'))
                if getconf('save_restore_messages_enabled'):
                    self.message_store.save_message("to:{}@{}".format(u,h), make_send_message(msg, date=datetime.now().astimezone()))
                beep('message_sent')
                ix = self.tbar.add_message(other, datetime.now(), 0, self.input.toPlainText(), is_from_net=False)
                self.tbar.select_conversation(other)
                # and clear the input field
                self.input.clear()
            except CLSError as m:
                # Typically "User not logged in" or "No server for this contact name"
                qInfo("CLS error: {!r}".format(m.message))
                QMessageBox.warning(self,"Chaosnet error","Error from host {}:<br>{}".format(self.remote_host(), m.message.rstrip("\0x00")))
            except ChaosError as m:
                beep('alert')
                qInfo("Chaosnet error: {!r}".format(m.message))
                if isinstance(m,ChaosSocketError):
                    QMessageBox.critical(self,"Chaosnet Error","<b>Chaosnet Error:</b><br>{}".format(m.message.rstrip("\0x00")))
                else:
                    QMessageBox.critical(self,"Chaosnet Error","<b>Chaosnet Error:</b> Error from host {}:<br>{}".format(self.remote_host(),m.message.rstrip("\0x00")))
            self.input.setReadOnly(False)

    def add_message(self, uname, host, date, diffhours, text, is_from_net):
        self.set_destination(uname, host, False) # don't switch to the destination
        self.tbar.add_message("{}@{}".format(uname,host), date, diffhours, text, is_from_net=is_from_net)

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
            qInfo("Invalid destination user {!r}".format(user))
        elif host is None or host == "":
            qInfo("Invalid destination host {!r}".format(host))
        else:
            # Since the text might not have been "activated" yet, just entered, add it to the menu
            di = self.cbox.find_destination(self.cbox.currentText())
            if di < 0:
                if self.cbox.insertPolicy() == QComboBox.InsertPolicy.InsertAtTop:
                    self.cbox.insertItem(0, self.cbox.currentText())
                    di = 0
                else:           # I assumed this followed the policy, but...
                    di = self.cbox.addItem(self.cbox.currentText())
                qDebug("set_destination: Saving destination index {}".format(di))
                settings.setValue('destination_list_index',di)
                if switch:
                    self.cbox.setCurrentIndex(di)
                    settings.setValue('destination_list',[self.cbox.itemText(i) for i in range(self.cbox.count())])
            else:
                if switch and self.cbox.currentIndex() != di:
                    # print("set_destination: changing index from {} to {}".format(self.cbox.currentIndex(), di), file=sys.stderr)
                    self.cbox.setCurrentIndex(di)
                    qDebug("set_destination (2): Saving destination index {}".format(di))
                    settings.setValue('destination_list_index', di)
                else:
                    # print("set_destination: not changing index from {} ({}, {})".format(self.cbox.currentIndex(), self.cbox.currentText(), switch), file=sys.stderr)
                    pass
                if switch and self.tbar.tabText(self.tbar.currentIndex()).lower() != self.cbox.currentText().lower():
                    # print("set_destination: switching conversation", file=sys.stderr)
                    self.tbar.select_conversation(self.cbox.currentText())

    def set_restore_conversations(self):
        v = self.restore_conversations_action.isChecked()
        qDebug("Setting Restore Conversations to {!r}".format(v))
        settings.setValue('restore_conversation_tabs', v)
        # @@@@ add tabs for all that are missing, e.g. after Edit destination list.
        if v and self.tbar.count() > 0 and self.tbar.is_dummy_page(): # Restore them when turned on
            for d in settings.value('destination_list'):
                self.tbar.add_conversation(d)

    def set_multi_line_messages(self):
        v = self.multi_line_messages_action.isChecked()
        qDebug("Setting Multi-line messages to {!r}".format(v))
        settings.setValue('multi_line_messages', v)
        # also change self.input and put it in the right layout
        def replace_input(new_input):
            for i in range(self.sendlayout.count()):
                # find it
                witem = self.sendlayout.itemAt(i)
                if isinstance(witem, QWidgetItem) and witem.widget() == self.input:
                    hf = witem.widget().hasFocus()
                    x = self.sendlayout.takeAt(i) # remove it
                    x.widget().hide()             # and hide it to be sure
                    self.sendlayout.insertWidget(i, new_input) # put in the new one
                    self.input = new_input
                    if hf:      # preserve focus status
                        self.input.setFocus()
                    return
            qDebug("Failed to replace input field!? still {!r}".format(self.input))
        if v and not isinstance(self.input, MessageInputMultiLine):
            qDebug("Installing new MessageInputMultiLine")
            old_txt = self.input.toPlainText()
            old_pos = self.input.cursorPosition() # get the QLineEdit position
            new = self.make_message_multiline()
            new.setPlainText(old_txt) # in case there was text in the old input field
            new_cursor = new.textCursor()
            new_cursor.setPosition(old_pos) # move the cursor
            new.setTextCursor(new_cursor)
            replace_input(new)
        elif not v and not isinstance(self.input, MessageInputBox):
            qDebug("Installing new MessageInputBox")
            old_txt = self.input.toPlainText()
            old_pos = self.input.textCursor().position() # get QPlainTextEdit position
            new = self.make_message_oneliner()
            new.setText(old_txt.replace("\n"," ")) # in case there was text in the old input field
            new.setCursorPosition(old_pos)         # update the position
            replace_input(new)

    def set_save_restore_messages(self, value=None):
        if value is None:
            checked = self.save_restore_messages_enabled_action.isChecked()
        else:
            checked = value
            self.save_restore_messages_enabled_action.setChecked(value)
        qDebug("Setting Destination checks enabled to {!r}".format(checked))
        settings.setValue('save_restore_messages_enabled', checked)
        self.message_store.init_conversation_save_file()

    def clear_saved_messages(self, force=False):
        if not force:
            r = QMessageBox.question(self, "Clear saved messages?",
                                     "Do you want to clear all saved messages?")
            if r == QMessageBox.StandardButton.No:
                if verbose:
                    qInfo("Cancelled clearing saved messages")
                return
        self.message_store.clear_messages()

    def set_conversation_save_file(self, fname=None):
        qDebug("set_conversation_save_file: {!r}".format(fname))
        if not fname:
            fname,filter = QFileDialog.getSaveFileName(self,
                                              "Save conversations messages here",
                                              os.path.dirname(getconf('conversation_save_file')),
                                              # filter=QDir.Filter.Files | QDir.Filter.Hidden | QDir.Filter.Writable,
                                              options=QFileDialog.Option.DontConfirmOverwrite)
        if fname and len(fname) > 0:
            if os.path.isfile(fname) and not os.access(fname, os.W_OK | os.R_OK):
                QMessageBox.information(self,"Not read/writable",
                                        "File not read/writable: {!r}".format(fname))
                return
            qDebug("Setting conversation_save_file to {!r}".format(fname))
            settings.setValue('conversation_save_file', fname)
            self.message_store.init_conversation_save_file()
        else:
            if verbose:
                qInfo("Cancelled setting message save file")

    def set_sound_effects(self):
        qDebug("Setting Sound effects to {!r}".format(self.sound_effects_action.isChecked()))
        settings.setValue('sound_effects', self.sound_effects_action.isChecked())
    def set_destination_checks_enabled(self, value=None):
        if value is None:
            checked = self.destination_checks_enabled_action.isChecked()
        else:
            checked = value
            self.destination_checks_enabled_action.setChecked(value)
        qDebug("Setting Destination checks enabled to {!r}".format(checked))
        old = getconf('watcher_enabled')
        if checked != old:
            settings.setValue('watcher_enabled', checked)
            self.refresh_action.setEnabled(checked)
            if checked:
                # self.destwatcher.unpause()
                self.destwatcher.paused = False
                self.start_all_watchers()
            else:
                self.destwatcher.pause()

    def start_all_watchers(self):
        # for all conversations, start_watcher.
        # If a conversation was added while watcher_enabled was false, it will not have an existing watcher,
        # so need to start one. If it does exist (paused), this re-sets the default interval, waking it up.
        for i in range(self.cbox.count()):
            self.destwatcher.start_watcher(self.cbox.itemText(i))
        pass

    def disable_unread_markers(self):
        self.tbar.set_messages_unread_disabled(True)
    def enable_unread_markers(self):
        self.tbar.set_messages_unread_disabled(False)
    def clear_all_unread_markers(self):
        self.tbar.set_messages_unread_for_all(False)

    def make_message_oneliner(self):
        new = MessageInputBox()
        # Set a validator to make the returnPressed only happen when non-empty, and only accept ASCII
        new.setValidator(QRegularExpressionValidator(QRegularExpression("[[:ascii:]]+"),new))
        new.returnPressed.connect(self.sendit)
        return new
    def make_message_multiline(self):
        new = MessageInputMultiLine()
        # @@@@ allow resizing?
        new.setup_height()
        return new

    def collect_all_destinations(self):
        # Collect all currently online destinations, asynchronously adding them using tbar.add_conversation.
        # First broadcast FINGER; if no response, broadcast LOAD to see which hosts to run NAME on.
        # @@@@ Generalize this:
        # - make it a PersistentWorker optionally running only once,
        # - parametrize what to do with discovered destinations (or rather, the finger/name data), prossibly a signal?
        # Then use it both for this and for the usual watcher (which then becomes more asynchronous in the NAME phase),
        # and for the generic finger/name data display thing (a QTableView using a ModelView, cf https://www.pythonguis.com/tutorials/pyqt6-qtableview-modelviews-numpy-pandas/)
        from PyQt6.QtCore import QThreadPool
        from watcher import Worker
        from chaosnet import ChaosSocketError, ChaosError, BroadcastFingerDict, BroadcastLoadDict, NameDict
        def finger_collector(subnets):
            result = []
            try:
                rs = BroadcastFingerDict(subnets).dict_result()
            except ChaosSocketError:
                raise
            except ChaosError as m:
                qDebug("Broadcast {} FINGER: {}".format(subnets, m))
            else:
                result = ["{}@{}".format(r['uname'],dns_name_of_address(r['source'], timeout=2)) for r in rs if len(r['uname']) > 0]
            if debug:
                qDebug("FINGER {} gives {}".format(subnets, result))
            return result
        def finger_result(result):
            for dest in result:
                if not self.tbar.find_conversation(dest):
                    qInfo("Found new destination {} (FINGER)".format(dest))
                    self.tbar.add_conversation(dest)
        def load_collector(subnets):
            result = []
            try:
                rs = BroadcastLoadDict(subnets).dict_result()
            except ChaosSocketError:
                raise
            except ChaosError as m:
                qDebug("Broadcast {} LOAD: {}".format(subnets, m))
            else:
                result = [dns_name_of_address(r['source'], timeout=2) for r in rs if r['users'] > 0]
            if debug:
                qDebug("LOAD {} gives {}".format(subnets, result))
            return result
        def name_collector(host):
            ulist = []
            try:
                start = time.time()
                if debug:
                    qDebug("Starting NAME for {}".format(host))
                r = NameDict(host, options=dict(timeout=5)).dict_result()
                if debug:
                    qDebug("Got NAME for {} in {:.2f}s: {!r}".format(host,time.time()-start,r))
            except ChaosSocketError:
                raise
            except ChaosError as m:
                qDebug("NAME {}: {}".format(host, m))
            else:
                # filter out not-logged-in jobs
                ulist = ["{}@{}".format(l['userid'],host) for l in r if not re.match(r"(___[0-9]{3})|(\?\?\?)", l['userid'])]
            if debug:
                qDebug("NAME {} gives {}".format(host, ulist))
            return ulist
        def name_result(result):
            for dest in result:
                if not self.tbar.find_conversation(dest):
                    qInfo("Found new destination {} (NAME)".format(dest))
                self.tbar.add_conversation(dest)
        def load_result(result):
            if debug:
                qDebug("LOAD result is {!r}".format(result))
            for host in result:
                nw = Worker(lambda progress_callback: name_collector(host))
                nw.signals.result.connect(name_result)
                if debug:
                    qDebug("LOAD starting worker for {}".format(host))
                tp.start(nw)
        try:
            self.collect_all_destinations_action.setEnabled(False)
            subnets = [-1]      # @@@@ configurable?
            tp = QThreadPool()
            finger_worker = Worker(lambda progress_callback: finger_collector(subnets))
            finger_worker.signals.result.connect(finger_result)
            if debug:
                qDebug("Starting FINGER worker for {}".format(subnets))
            tp.start(finger_worker)
            load_worker = Worker(lambda progress_callback: load_collector(subnets))
            load_worker.signals.result.connect(load_result)
            if debug:
                qDebug("Starting LOAD worker for {}".format(subnets))
            tp.start(load_worker)
            # qInfo("Waiting for Done")
            # qInfo("Done: {!r}".format(tp.waitForDone(60*1000)))
        finally:
            self.collect_all_destinations_action.setEnabled(True)

    def closeEvent(self,event):
        settings.setValue("MainWindowSize",self.size())
        settings.setValue("MainWindowPosition",self.pos())
        # event.accept()
        super().closeEvent(event)

    # never activated?
    def focusChange(self,old,new):
        qDebug("Focus change: from {!r} to {!r}".format(old,new))

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
        def boolean_setting_action(title, handler, conf, shortcut=None):
            # @@@@ should generate handler based on conf
            a = make_action(title, handler, shortcut=shortcut)
            a.setCheckable(True)
            a.setChecked(getconf(conf))
            return a
        def make_icon_color_action(title, conf):
            act = QAction(title, self)
            act.setIcon(self.make_icon(getconf(conf)))
            act.triggered.connect(lambda: self.set_icon_color(conf, act))
            return act
        # Create the application menu
        self_menu = self.menuBar()
        my_menu = self_menu.addMenu(app.applicationName())
        aboutaction = make_action("About {}".format(app.applicationName()), self.aboutme)
        my_menu.addAction(aboutaction)
        my_menu.addAction(make_action("Send message", self.sendit, shortcut="Ctrl+S"))
        my_menu.addSeparator()
        self.refresh_action = make_action("Refresh online status", self.destwatcher.refresh_all_watchers,
                                          shortcut="Ctrl+R")
        self.refresh_action.setEnabled(getconf('watcher_enabled'))
        my_menu.addAction(self.refresh_action)
        self.collect_all_destinations_action = make_action("Collect all online users", self.collect_all_destinations)
        my_menu.addAction(self.collect_all_destinations_action)

        settings_menu = self_menu.addMenu("Settings")
        settings_menu.addAction(make_action("Edit destination menu", self.cbox.edit_destination_list))
        settings_menu.addAction(make_action("Clear destination menu", self.cbox.clear_destination_list))
        settings_menu.addAction(make_action("Clear all conversations", self.clear_all_conversations))
        settings_menu.addAction(make_action("Remove all conversations", self.remove_all_conversations))
        settings_menu.addSeparator() # ----------------------------------------------------------------
        self.sound_effects_action = boolean_setting_action("Sound effects enabled",
                                                           self.set_sound_effects,
                                                           'sound_effects')
        settings_menu.addAction(self.sound_effects_action)
        self.restore_conversations_action = boolean_setting_action("Restore conversation tabs on restart", 
                                                                   self.set_restore_conversations,
                                                                   'restore_conversation_tabs')
        settings_menu.addAction(self.restore_conversations_action)
        self.multi_line_messages_action = boolean_setting_action("Use multi-line messages",
                                                                 self.set_multi_line_messages,
                                                                 'multi_line_messages',
                                                                 shortcut="Ctrl+Shift+M")
        settings_menu.addAction(self.multi_line_messages_action)
        settings_menu.addAction(make_action("Set lines in multi-line message input...",
                                            self.set_multi_line_message_lines))
        settings_menu.addSeparator() # ----------------------------------------------------------------
        save_restore_menu = settings_menu.addMenu("Save/restore messages")
        self.save_restore_messages_enabled_action = boolean_setting_action("Save/restore messages between sessions",
                                                                           self.set_save_restore_messages,
                                                                           'save_restore_messages_enabled')
        save_restore_menu.addAction(self.save_restore_messages_enabled_action)
        save_restore_menu.addAction(make_action("Clear stored messages",
                                            self.clear_saved_messages))
        save_restore_menu.addAction(make_action("Set message store file...",
                                            self.set_conversation_save_file))
        settings_menu.addSeparator() # ----------------------------------------------------------------
        online_menu = settings_menu.addMenu("Online checks")
        self.destination_checks_enabled_action = boolean_setting_action("Enable destination online checks",
                                                                        self.set_destination_checks_enabled,
                                                                        'watcher_enabled')
        online_menu.addAction(self.destination_checks_enabled_action)
        online_menu.addAction(make_action("Set destination checking interval...", self.set_online_interval))
        online_menu.addAction(make_action("Set idle limit...", self.set_idle_limit))
        online_menu.addAction(make_action("Set away limit...", self.set_away_limit))
        ic = make_icon_color_action("Edit idle user color...", 'idle_icon_color')
        ac = make_icon_color_action("Edit away user color...", 'away_icon_color')
        # to use when resetting settings
        self.icon_color_actions = dict(idle_icon_color=ic, away_icon_color=ac)
        online_menu.addAction(ic)
        online_menu.addAction(ac)
        online_menu.addAction(make_action("Reset user status colors to defaults", self.reset_icon_colors))
        settings_menu.addSeparator() # ----------------------------------------------------------------
        settings_menu.addAction(make_action("Set send timeout...", self.set_message_timeout))
        settings_menu.addAction(make_action("Set domain search list...", self.set_dns_search_list))
        settings_menu.addAction(make_action("Set DNS server...", self.set_dns_server))
        settings_menu.addSeparator() # ----------------------------------------------------------------
        color_menu = settings_menu.addMenu("Background colors")
        self.background_color_action = make_action("Edit background color...", self.set_background_color,
                                                   icon=self.make_icon(getconf('background_color')))
        color_menu.addAction(self.background_color_action)
        self.from_net_color_action = make_action("Edit net message background color...", 
                                                 self.set_background_color_from_net,
                                                 icon=self.make_icon(getconf('from_net_color')))
        color_menu.addAction(self.from_net_color_action)
        self.from_me_color_action = make_action("Edit my message background color...", 
                                                self.set_background_color_from_me,
                                                icon=self.make_icon(getconf('from_me_color')))
        color_menu.addAction(self.from_me_color_action)
        color_menu.addAction(make_action("Reset background colors to defaults",
                                            self.reset_background_colors))
        settings_menu.addSeparator() # ----------------------------------------------------------------
        settings_menu.addAction(make_action("Reset all settings", self.reset_settings))
        
        conv_menu = self_menu.addMenu("Conversation")
        conv_menu.addAction(make_action("Clear current conversation", self.clear_current_conversation))
        conv_menu.addAction(make_action("Remove current conversation", self.remove_current_conversation))
        conv_menu.addAction(make_action("Remove current destination", self.remove_current_destination))

    def init_layout_and_boxes(self):
        # Put the messages in separate conversation tabs
        self.tbar = ConversationTabs()
        
        # now the part for the input and Send button
        self.sendlayout = QHBoxLayout()
        self.sendbutton = QPushButton("Send", self)
        self.sendbutton.setDefault(True) # Make it a nice big button
        # Disabling the button makes it almost invisible (on macOS). Instead have sendit handle it.
        # self.sendbutton.setEnabled(False)
        self.sendbutton.clicked.connect(self.sendit)
        self.sendlayout.addWidget(self.sendbutton)

        if getconf('multi_line_messages'):
            self.input = self.make_message_multiline()
        else:
            self.input = self.make_message_oneliner()
        self.sendlayout.addWidget(self.input)

        destlayout = QHBoxLayout()
        destlayout.addWidget(QLabel("Destination:"), alignment=Qt.AlignmentFlag.AlignLeft)
        self.cbox = DestinationSelector(self)
        self.cbox.set_tabbar(self.tbar) # tie them together
        self.tbar.set_destbox(self.cbox)
        # Watch the destinations online/offline etc
        self.destwatcher = ConverseDestWatcher()
        self.destwatcher.set_debug(debug)
        self.destwatcher.set_interval(getconf('watcher_interval'))
        if not getconf('watcher_enabled'):
            self.destwatcher.pause()
        self.destwatcher.set_tabbar(self.tbar)
        # End all the workers when application quits.
        def end_all_watchers():
            if self.screen_lock_watcher:
                self.screen_lock_watcher.stop_screen_lock_watcher()
            self.receiver.stop_receiver()
            self.destwatcher.end_all_watchers() # @@@@ this should abort their conns (like the receiver does)
        app.aboutToQuit.connect(end_all_watchers)
        self.tbar.set_watcher(self.destwatcher)
        if QSysInfo.productType() == "macos":
            # Watch for screen locks, and pause/restart the destination watcher
            self.screen_lock_watcher = ScreenLockWatcher(self.destwatcher)
            self.screen_lock_watcher.start_screen_lock_watcher()
        else:
            qInfo("Please implement 'screen_is_locked' for this operating system ({})".format(QSysInfo.productType()))

        destlayout.addWidget(self.cbox, alignment=Qt.AlignmentFlag.AlignLeft)
        destlayout.addStretch(1)

        # Make a pane for showing errors, without using a popup.
        self.error_pane = self.statusBar()
        self.error_pane.setStyleSheet("border: 2px solid #FF2F92;")
        # Don't show the pane until necessary
        self.error_pane.setVisible(False)
        def error_pane_changed(msg):
            if msg == "":
                self.error_pane.setVisible(False)
        self.error_pane.messageChanged.connect(error_pane_changed)

        # The top-level layout: messages followed by input
        toplayout = QVBoxLayout()
        # toplayout.addWidget(self.error_pane)
        toplayout.addWidget(self.tbar)
        toplayout.addLayout(destlayout)
        toplayout.addLayout(self.sendlayout)
        topwidget = QWidget()
        topwidget.setLayout(toplayout)

        self.setCentralWidget(topwidget)

        self.input.setFocus()   # after showing it (by setCentralWidget)

    def init_stylesheet(self):
        app.setStyleSheet(app.styleSheet()+
                          "MessageDisplayBoxLeft {"+
                          " background-color: {}; ".format(getconf('from_net_color'))+
                          " color: {};".format("white" if qGray(QColor(getconf('from_net_color')).rgba()) < 128 else "black")+
                          "}\n"+
                          "MessageDisplayBoxRight {"+
                          " background-color: {}; ".format(getconf('from_me_color'))+
                          " color: {};".format("white" if qGray(QColor(getconf('from_me_color')).rgba()) < 128 else "black")+
                          "}\n")
        if debug:
            qDebug("app styleSheet now:")
            qDebug(app.styleSheet())

    def __init__(self):
        super().__init__()
        self.prev_msg_datetime = None
        self.last_other = None

        self.setWindowTitle("Chaosnet Converse {}".format(app.applicationVersion()))
        # Initialize settings
        set_dns_resolver_address(getconf('dns_server'))
        self.resize(getconf('MainWindowSize'))
        if getconf("MainWindowPosition"):
            self.move(getconf("MainWindowPosition"))

        # initialize layout etc
        self.init_layout_and_boxes()
        self.init_stylesheet()
        di = settings.value('destination_list_index') # get this before doing the add_conversation below
        if settings.value('destination_list'):
            self.cbox.insertItems(0,settings.value('destination_list'))
            if getconf('restore_conversation_tabs'):
                for d in settings.value('destination_list'):
                    if "@" in d:
                        if verbose or debug:
                            qInfo("Adding conversation for {!r}".format(d))
                        self.tbar.add_conversation(d)
                    else:
                        if verbose or debug:
                            qInfo("Bad destination {!r} in destination_list {!r}".format(d, settings.value('destination_list')))
                        break

        if di is not None:
            qDebug("Setting destination index {}".format(di))
            self.cbox.setCurrentIndex(di)

        # initialize menus
        self.init_menus()

        if reset_on_startup:
            self.reset_settings(True)

        self.message_store = MessageStorage(self)
        if getconf('save_restore_messages_enabled'):
            self.message_store.restore_messages()

        # Start the receiver
        self.receiver = MessageReceiver(self)
        # self.receiver.set_debug(True)
        self.receiver.start_receiver()

# https://www.pythonguis.com/faq/command-line-arguments-pyqt6/
def parse_args(app):
    parser = QCommandLineParser()
    parser.setApplicationDescription(app.applicationName()+" is a program to have conversations on Chaosnet.")
    parser.addHelpOption()
    parser.addVersionOption()
    # @@@@ maybe check if we're in DNS and then don't add this option.
    copt = QCommandLineOption(["c","chaoshost"],"Set my Chaosnet hostname (if your hostname is not in Chaos DNS)","chaosname")
    iopt = QCommandLineOption(["i","interval"],"Watcher interval","interval")
    dopt = QCommandLineOption(["d","debug"],"Debug messages")
    vopt = QCommandLineOption(["V","verbose"],"Verbose messages")
    ropt = QCommandLineOption(["R","reset"],"Reset all settings")
    dumpopt = QCommandLineOption(["D","dump-settings"],"Dump all settings")
    parser.addOption(dopt)
    parser.addOption(vopt)
    parser.addOption(copt)
    parser.addOption(iopt)
    parser.addOption(ropt)
    parser.addOption(dumpopt)
    parser.process(app)
    if parser.isSet(dopt):
        global debug
        debug = True
    if parser.isSet(vopt):
        global verbose
        verbose = True
    if parser.value(iopt):
        settings.setValue('watcher_interval', int(parser.value(iopt)))
        if verbose or debug:
            qInfo("Set watcher_interval to {}".format(getconf('watcher_interval')))
    if parser.isSet(ropt):
        global reset_on_startup
        reset_on_startup = True
    if parser.isSet(dumpopt):
        qInfo("Settings:")
        for k in ["MainWindowPosition"] + list(default_config.keys()):
            qInfo(" {} = {!r}".format(k, getconf(k)))
    return parser.value(copt)

if __name__ == '__main__':
    from socket import getfqdn
    chost = parse_args(app)
    if chost:
        if chost.lower() != getfqdn().lower() and dns_addr_of_name_search(getfqdn()):
            # maybe refuse
            qInfo("%% Spoofing Chaosnet hostname")
        if re.match(r"^[\w_.-]+[^.]$", chost) and dns_addr_of_name_search(chost):
            qInfo("Using Chaosnet hostname {!r}".format(chost))
            # NOTE: not saving this persistently, in order to discover changes
            default_config['my_chaos_hostname'] = chost
        else:
            qWarning("Bad Chaosnet hostname {!r}".format(chost))
            exit(1)
    else:
        if dns_addr_of_name_search(getfqdn()) is None:
            from chaosnet import host_name_and_addr
            # Get the local cbridge's name and address (using STATUS)
            name,addr = host_name_and_addr("localhost")
            # name might be a shortname or a "Pretty and Silly String", so find the DNS name of the address
            fqdn = dns_name_of_address(addr)
            if fqdn is None:
                qWarning("Your host name {!r} is not in Chaosnet DNS, and neither is your local address {:o}. You might need to use the --chaoshost option.".format(getfqdn(), addr))
                if name is not None:
                    # Use the silly name anyway, in case this is on a private net
                    qInfo("Using Chaos hostname {!r} ({:o})".format(name.replace(" ","-"), addr))
                    # NOTE: not saving this persistently, in order to discover changes
                    default_config['my_chaos_hostname'] = name.replace(" ","-")
            else:
                qDebug("Using Chaos hostname {!r} ({:o}, {!r})".format(fqdn, addr, name))
                # NOTE: not saving this persistently, in order to discover changes
                default_config['my_chaos_hostname'] = fqdn

    try:
        if not debug and not verbose:
            # Just ignore all qDebug printouts
            qDebug = lambda x: x
            pass

        main_window = MainWindow()
        main_window.show()

        # Start the event loop.
        app.exec()
    except RuntimeError as m:
        print(m, file=sys.stderr)
