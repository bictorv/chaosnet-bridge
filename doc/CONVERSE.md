# Converse

Converse is a program to have conversations over Chaosnet. It is inspired by the Converse system on Lisp Machines.

Converse is a client and server for the standard [SEND protocol](https://chaosnet.net/amber.html#Send) on Chaosnet. It uses the [NCP API](NCP.md) of cbridge (and thus requires cbridge to be running locally and with ncp enabled).

It assumes messages will only (meaningfully) arrive for the user running Converse, i.e., that there are no other users logged in.

It makes use of `qsend.py`, which can also be used as a command-line client for sending messages. Try `qsend.py --help`.

## User interface

There are three parts of the user interface:
1. a Conversation part, where tabs show the Message history for each conversation (incoming and outgoing messages)
2. a Destination selector, indicating where messages will be sent
3. a message Input window, where you type the message to be sent before clicking the Send button.

There is also a Converse menu (at least one), a Settings menu, and a Conversation menu. And an About item.

### Conversation
Each conversation is put in a separate tab, showing the message history for a conversation party.
The message history shows incoming and outgoing messages, with timestamps. New messages appear at the bottom of the message history, scrolling older messages upwards.

Incoming messages are left-adjusted and in a (by default yellowish) color. Outgoing messages are right-adjusted and in a (by default blue-ish) color.

If the most recent message is sent/received on a new date, the date is shown before the message.

If a message arrives to a conversation whose tab is not selected, a little red dot is added to the tab label.

If there is only one conversation, the tab header is not shown. (*Give me feedback on this?*)

If a message arrives when the Converse window is not the focused/active window, an attempt is made to "bounce" the application icon (e.g. in the Dock, on macOS).

The Conversation menu allows clearing the current conversation tab, removing it altogether, and removing the current destination from the destination input drop-down menu.

To clear all conversation histories, use `Clear all conversations` in the Settings menu. 
To remove all conversation tabs, use `Remove all conversations` in the Settings menu.

### Destination input

The destination can be input in this part, using the syntax `user@host`, where `user` is the remote userid and `host` is the name of a Chaosnet host. If the destination is new, it will be saved and can be selected from the drop-down menu.

If a "shortname" for the `host` is used, an attempt is made to expand the shortname into a fully qualified domain name. E.g., if `victor@up` is input, it will/should be expanded to `victor@UP.dfUpdate.SE`.

The destination list can be edited using the `Edit destination menu` menu item, and cleared by the `Clear destination menu`.
To remove the currently selected destination from the list, use `Remove current destination` from the Conversation menu.

### Message Input

The message to be sent is input here. You can send it by pressing [Enter], [Control-S] (or [Command-S] on macOS), or using the `Send message` menu item.

## Settings

The window geometry and position is saved between sessions. Also destinations are saved, and attempts are made to preserve the currently selected destination.

In the Settings menu:
- You can edit the destination menu, or clear it.
- You can clear all conversations, or remove them all.
- You can set the timeout for sending messages (default 5 seconds) using the `Set send timeout` menu item.
- You can set the domain name search list using the `Set domain search list` menu item. This is used if you specify a destination `host` without a domain, e.g. `up`. The domain names are appended to the `host` and looked up until a match is found.
- You can specify the DNS server to use for Chaosnet-class requests (default `dns.chaosnet.net`). Note that almost all DNS servers in the world are incapable of finding Chaosnet-class DNS information, so you probably do not want to change this setting.
- You can edit the window background color (default light grey, which makes the white input fields easier to see I think) using the `Edit background color` menu item.
- You can edit the background colors of messages in the Message history using the `Edit net message background color` and `Edit my message background color` menu items. Note that this only affects how the Converse program displays messages (e.g. the destination will not see the color).

You can also reset all settings by using the `Reset all settings` menu item. This also moves and resizes the Converse window to the default position/size.

## Installation and requirements

Requirements: dnspython, pyqt6.

Doing `make` in the `tools` subdirectory uses [pyinstaller](https://pyinstaller.org/en/stable/) to produce an app from the python sources. If `pip3 install PyInstaller` doesn't put pyinstaller in your `PATH`, please see a comment in [Makefile](Makefile).

## Future plans/features

- [ ] The message input window should (optionally?) support multi-line input (using QPlainTextEdit instead of QTextEdit).
- [ ] Sending the message should be done in a separate thread, so it can be interrupted/cancelled if it takes too long time.
- [ ] Incoming/outgoing messages should be saved to disk and restored when Converse is restarted.
- [ ] There should be some (optional) sound effect when a message is received (and perhaps sent). *But I can't get `QSoundEffect` to work on my Mac.* :-(
- [ ] There should be some display of whether saved destinations are online, and non-idle. *Implementation idea: use the STATUS protocol to see if the host is up, the FINGER protocol which gives a quick response if it is supported, and otherwise the NAME protocol (where the output needs parsing).*
- [ ] You may want to set an auto-reply (if you go AFK), and there should be a setting for at what idle time the auto-reply is sent. *(And it should ideally be sent if your screen is locked, too.) (Perhaps the auto-reply should be implemented using a CLS packet with the message, to avoid auto-auto-replies?)*
- [ ] There could be a Dock icon counter for unseen incoming messages, on macOS.
- [ ] You could dream of a "group chat" setting, which automatically sends messages to a set of destinations. *Need to handle replies sensibly though (so they go to all in the group). Probably a new/compatible protocol for group handling, which uses SEND for transport?*

Let me know if you (want to) implement any of this, or if you have more ideas!

## Known issues

- When you change the message background colors, old messages are not re-coloured.
- An attempt at setting an icon for the menu items for editing colors, but this does not always have effect in PyQt6 on macOS. *Probably depends on installation issues.*
- QSoundEffect doesn't seem to work in either PyQt6 or PySide6, on my Mac.
