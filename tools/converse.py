#!/usr/bin/env python3
# Copyright © 2025 Björn Victor (bjorn@victor.se)
# This is a Converse (i.e. SEND) client, vaguely reminiscent of Converse on LISPM.

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
# - beeps when message incoming
# - save configuration and window geometry
# - (optionally) save incoming msgs to disk and restore them on restart
#
# Configuration:
# - colors of fields/msgs
# - sounds on/off
# - receiver on/off (related to if the screen is on, or idle, or ...)
# Future features: autoreply, idle detection, ignore lists...

# SEND protocol message format:
# - RFC arg: destinationUsername
# - line 1: from@host date-and-time
# - rest: message. ITS starts it with "To:" header (cf COMSAT).
#
# @@@@ For sending, need to know our Chaos host name, which might be different from "actual" host name.
# @@@@ May add "ID" operation for cbridge NCP to return useful things like addresses, full hostname, pretty hostname
# @@@@ Make this a config/parameter here for now.
#
# TODO:
# Put each conversation in a container which scrolls if it's too high. Add title to show other end.
# Put an input window at the bottom of each conversation.
# Put an empty conversation at the very bottom, to start a new one.
# Perhaps put each conversation in its own window, and have a menu item/command-N to create a new one,
# prompting for destination? With QCompleter for host names? :-)
#
# Add menu bar with minimal content: Quit, New conversation, Next/Previous conversation.
#
# TODO:
# Verify that the destination has a valid Chaos host.
# Verify that the source "from" part matches the source address

import sys, re
from chaosnet import ChaosError, dns_name_of_address, dns_addr_of_name, dns_addr_of_name_search, set_dns_resolver_address

config = dict(# date_color="#ffebee", 
              from_net_color="#ffc",
              from_me_color="#e1f5fe",
              # Sigh.
              dns_search_list=["chaosnet.net","victor.se","dfupdate.se"],
)
def getconf(opt):
    if opt in config:
        return config[opt]
    else:
        return None

# For now, try pyqt6.

# Cf https://www.pythonguis.com/tutorials/pyqt6-creating-your-first-window/,
# https://www.riverbankcomputing.com/static/Docs/PyQt6/api/qtwidgets/qtwidgets-module.html
# https://www.pythonguis.com/tutorials/pyqt6-qscrollarea/

from PyQt6.QtCore import Qt
from PyQt6.QtCore import QCommandLineOption, QCommandLineParser, QRegularExpression
from PyQt6.QtWidgets import (QPlainTextEdit, QTextEdit, QMainWindow, QSpacerItem, QSizePolicy)
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLabel, QFrame, QSpacerItem, QMessageBox, QComboBox,
                             QSizePolicy, QScrollArea, QLineEdit, QMenuBar)
from PyQt6.QtGui import QAction, QRegularExpressionValidator

################  get messages from cbridge

# cf https://github.com/pyqt/examples/blob/_/src/11%20PyQt%20Thread%20example/03_with_threadutil.py
from threading import Thread
from threadutil import run_in_main_thread
from time import sleep

new_messages = []
def fetch_new_messages(win):
    from chaos_send import get_send_message
    def add_message(win,uname,host,text):
        sender = ""
        ru, rh = win.remote_user(),win.remote_host()
        if ru is None or rh is None or uname.lower() != ru.lower() or host.lower() != rh.lower():
            win.set_destination(uname,host)
            sender = "{}@{}".format(uname,host)
        win.makeBox(text, other=sender, is_from_net=True)
        win.last_other = sender
        # @@@@ optionally beep (setting)
    # The trick: run add_message in the main thread
    am = run_in_main_thread(add_message)
    from getpass import getuser
    me = getuser()
    from socket import getfqdn
    myhost = getfqdn()
    while True:
        try:
            destuser,uname,host,date,text = get_send_message()
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
    def sendit(self):
        from chaos_send import send_message
        if not self.remote_host() or not self.remote_user():
            # @@@@ Beep
            QMessageBox.critical(self,"Error","Destination user/host unknown!",
                                 buttons=QMessageBox.StandardButton.Ok)
            return
        # Expand destination host (sigh, searchlist configuration...)
        destaddr = dns_addr_of_name_search(self.remote_host(),searchlist=getconf('dns_search_list'))
        if destaddr is None:
            QMessageBox.critical(self,"Error","Destination host {!r} unknown on Chaosnet".format(self.remote_host()),
                                 buttons=QMessageBox.StandardButton.Ok)
            return
        if len(self.input.text()) > 0:
            u,h = self.remote_user(), self.remote_host()
            desthost = dns_name_of_address(destaddr[0])
            if desthost:
                print("Setting dest to {!r} (canonical name of {!r})".format(desthost, h))
                h = desthost
            self.set_destination(u,h)
            # first lock the input, send it, and when it's sent, unlock (in case it takes time)
            print("Sending {!r} to {}@{}".format(self.input.text(), u,h), 
                  file=sys.stderr)
            self.input.setReadOnly(True)
            try:
                # @@@@ need a cancel button, and a timeout setting
                # @@@@ probably need to run send_message in another thread then?
                send_message(u,h, self.input.text())
                other = "{}@{}".format(u,h)
                # need to keep track of who we sent last msg to, and add sender arg if it changed.
                if other != self.last_other:
                    self.makeBox(self.input.text(), is_from_net=False, other=other)
                    self.last_other = other
                else:
                    self.makeBox(self.input.text(), is_from_net=False)
                # and clear the input field
                self.input.clear()
            except ChaosError as m:
                # @@@@ Beep
                QMessageBox.critical(self,"Chaosnet Error","Error from host {}: {}".format(self.remote_host(),m.message),
                                     buttons=QMessageBox.StandardButton.Ok)
            self.input.setReadOnly(False)
            self.enable_input()

    def makeline(self, width=100):
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        line.setMinimumWidth(width)
        return line

    def makeBox(self,text,is_from_net=True,other=""):
        from datetime import datetime
        # If self.last_msg_time is a different day than today, add a line with today's date
        if self.prev_msg_datetime is None or datetime.now().date() != self.prev_msg_datetime.date():
            dbox = QHBoxLayout()
            dbox.setContentsMargins(0, 0, 0, 0)
            dbox.addWidget(self.makeline(), alignment=Qt.AlignmentFlag.AlignRight)
            d = QLabel(datetime.now().date().strftime("%e %b %Y"))
            d.setScaledContents(True)
            dbox.addWidget(d, alignment=Qt.AlignmentFlag.AlignCenter)
            dbox.addWidget(self.makeline(), alignment=Qt.AlignmentFlag.AlignLeft)
            dw = QWidget()
            dw.setLayout(dbox)
            if getconf("date_color"):
                dw.setStyleSheet('background-color: {};'.format(getconf('date_color')))
            self.msglayout.addWidget(dw, alignment=Qt.AlignmentFlag.AlignHCenter)
            self.prev_msg_datetime = datetime.now()
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        # timestamp @@@@ from incoming msg?
        if other != self.last_other:
            tbox = QVBoxLayout()
            tbox.setContentsMargins(0, 0, 0, 0)
            tbox.setSpacing(0)
            tbox.addWidget(QLabel(datetime.now().strftime('%H:%M:%S')))
            tbox.addWidget(QLabel(other))
            time = QWidget()
            time.setLayout(tbox)
        else:
            time = QLabel(datetime.now().strftime('%H:%M:%S'))
        box = MsgBox()
        box.setText(text)
        if is_from_net:         # text on the left
            if getconf("from_net_color"):
                box.setStyleSheet("background-color: {};".format(getconf('from_net_color')))
            align = Qt.AlignmentFlag.AlignLeft
            contents = [box, time]
        else:                   # on the right
            if getconf("from_me_color"):
                box.setStyleSheet("background-color: {};".format(getconf('from_me_color')))
            align = Qt.AlignmentFlag.AlignRight
            contents = [time, box]
        for c in contents:
            row.addWidget(c, alignment=align)
        w = QWidget()
        w.setLayout(row)
        self.msglayout.addWidget(w, alignment=align)

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

    def set_destination(self, user=None, host=None):
        if user is None or user == "":
            print("Invalid destination user {!r}".format(user), file=sys.stderr)
        elif host is None or host == "":
            print("Invalid destination host {!r}".format(host), file=sys.stderr)
        else:
            self.cbox.setCurrentText("{}@{}".format(user, host))
            # Since the text might not have been "activated" yet, just entered, add it to the menu
            # @@@@ perhaps "expand" it by doing DNS lookup and using the canonical name?
            if self.cbox.findText(self.cbox.currentText()) < 0:
                print("adding new destination {!r}".format(self.cbox.currentText()), file=sys.stderr)
                if self.cbox.insertPolicy() == QComboBox.InsertPolicy.InsertAtTop:
                    self.cbox.insertItem(0, self.cbox.currentText())
                else:           # I assumed this followed the policy, but...
                    self.cbox.addItem(self.cbox.currentText())

    def enable_input(self):
        if len(self.input.text()) > 0 and len(self.cbox.currentText()) > 0:
            self.sendbutton.setEnabled(True)
        else:
            self.sendbutton.setEnabled(False)

    def __init__(self):
        super().__init__()
        self.prev_msg_datetime = None
        self.last_other = None

        self.setWindowTitle("Chaosnet Converse")
        self.resize(600,400)    # @@@@ make this depend on font size

        # Put the messages in a vertically scrolling container
        scroll = AutoBottomScrollArea()  # contains the widgets, set as the centralWidget
        widget = QWidget() # widget that contains the collection of Vertical Box
        self.msglayout = QVBoxLayout()  # the vertical box that contains the MsgBoxes

        h = QLabel()
        h.setTextFormat(Qt.TextFormat.RichText)
        h.setText("<i>Message history</i>")
        self.msglayout.addWidget(h, alignment=Qt.AlignmentFlag.AlignCenter)
        # Keep a stretch at the top of the messages, so new msgs are at the bottom, next to the input box
        self.msglayout.addStretch(1)

        widget.setLayout(self.msglayout)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        scroll.setWidgetResizable(True)
        scroll.setWidget(widget)
        
        # now the part for the input and Send button
        hlayout = QHBoxLayout()
        self.sendbutton = QPushButton("Send", self)
        self.sendbutton.setDefault(True) # Make it a nice big button
        self.sendbutton.setEnabled(False)
        self.sendbutton.clicked.connect(self.sendit)
        hlayout.addWidget(self.sendbutton)
        # @@@@ maybe QPlainTextEdit, for multi-line input.
        # @@@@ For validation (ascii only), see answer by Judah Benjamin on
        # @@@@ https://www.devasking.com/issue/how-to-restrict-user-input-in-qlineedit-in-pyqt
        self.input = QLineEdit()
        # Set a validator to make the returnPressed only happen when non-empty, and only accept ASCII
        self.input.setValidator(QRegularExpressionValidator(QRegularExpression("[[:ascii:]]+"),self.input))
        # Disable the button, initially
        self.input.returnPressed.connect(self.sendit)
        # Enable it when there is text in the input field
        self.input.textEdited.connect(self.enable_input)
        hlayout.addWidget(self.input)
        # @@@@ make the "sender" item be clickable to update the dest?
        destlayout = QHBoxLayout()
        destlayout.addWidget(QLabel("Destination:"), alignment=Qt.AlignmentFlag.AlignLeft)
        self.cbox = QComboBox()
        self.cbox.setMinimumWidth(300)
        self.cbox.setEditable(True)
        self.cbox.setInsertPolicy(QComboBox.InsertPolicy.InsertAtTop) # alphabetically?
        self.cbox.setValidator(QRegularExpressionValidator(QRegularExpression(r"[\w_.-]+@[\w_.-]+"),self))
        destlayout.addWidget(self.cbox, alignment=Qt.AlignmentFlag.AlignLeft)
        destlayout.addStretch(1)
        # @@@@ add a "remove" button to remove the current index (except 0)

        # The top-level layout: messages followed by input
        toplayout = QVBoxLayout()
        toplayout.addWidget(scroll)
        toplayout.addLayout(destlayout)
        toplayout.addLayout(hlayout)
        topwidget = QWidget()
        topwidget.setLayout(toplayout)

        self.setCentralWidget(topwidget)

        self.input.setFocus()   # after showing it (by setCentralWidget)

        # Create the application menu:
        # - Send message (in the focused input box),
        # - Clear history
        # - Clear destinations
        # @@@@ add "About" etc
        # cf https://www.riverbankcomputing.com/static/Docs/PyQt6/api/qtwidgets/qmenubar.html
        self_menu = self.menuBar()
        my_menu = self_menu.addMenu("Converse")
        # @@@@ if we have >1 window, self needs to change. Use the button instead!
        qaction = QAction("Send message", self)
        qaction.setShortcut("Ctrl+S")
        qaction.triggered.connect(self.sendit)
        my_menu.addAction(qaction)

# https://www.pythonguis.com/faq/command-line-arguments-pyqt6/
def parse(app):
    parser = QCommandLineParser()
    parser.addHelpOption()
    parser.addVersionOption()
    hopt = QCommandLineOption(["r","remotehost"],"Remote hostname","hostname")
    uopt = QCommandLineOption(["u","remoteuser"],"Remote user","username")
    parser.addOption(hopt)
    parser.addOption(uopt)
    parser.process(app)
    return parser.value(hopt), parser.value(uopt)

# You need one (and only one) QApplication instance per application.
# Pass in sys.argv to allow command line arguments for your app.
# If you know you won't use command line arguments QApplication([]) works too.
app = QApplication(sys.argv)
app.setApplicationName("Converse")
app.setApplicationVersion("0.0.2")
app.setStyleSheet("QMainWindow{background-color: #eee;}")

rhost, ruser = parse(app)

# Create a Qt widget, which will be our window.
window = MainWindow()
if rhost and ruser:
    print("User: {!r}, Host: {!r}".format(ruser, rhost), file=sys.stderr)
    window.set_destination(ruser,rhost)
window.show()

# Run the SEND server thread
thread = Thread(target=fetch_new_messages, args=(window,), daemon=True)
thread.start()

# Start the event loop.
app.exec()
