# Converse

Converse is a program to have conversations over Chaosnet. It is inspired by the Converse system on Lisp Machines.

Converse features:
- a GUI for sending and receiving messages over Chaosnet
- (optional) sound effects when messages are received (and sent)
- (optional) markers for users indicating their online status and idleness (so you know if they are there)
- time difference indicated in message timestamps (for conversations between different timezones)
- (optionally) saving and restoring received and sent messages when Converse is restarted

Converse is a client and server for the standard [SEND protocol](https://chaosnet.net/amber.html#Send) on Chaosnet. It uses the [NCP API](NCP.md) of cbridge (and thus requires cbridge to be running locally and with ncp enabled).

It assumes messages will only (meaningfully) arrive for the user running Converse, i.e., that there are no other users logged in.

It makes use of `qsend.py`, which can also be used as a command-line client for sending messages. Try `qsend.py --help`.
It also uses the python library `watcher.py` (included).

## User interface

There are three parts of the user interface:
1. a Conversation part, where tabs show the Message history for each conversation (incoming and outgoing messages)
2. a Destination selector, indicating where messages will be sent
3. a message Input window, where you type the message to be sent before clicking the Send button.

There is also a Converse menu (at least one), a Settings menu, and a Conversation menu. Additionally an About item.

### Conversation
Each conversation is put in a separate tab, showing the message history for a conversation party.
The message history shows incoming and outgoing messages, with timestamps (in your local timezone). New messages appear at the bottom of the message history, scrolling older messages upwards. Timestamps for messages from other timezones indicate the timezone difference (e.g. +9h, -9h) - note that the timestamp itself is in your local time.

A sound effect is played when a message is received (and when one is sent, and when an error occurs). You can turn off sound effects by disabling the `Sound effects enabled` item in the Settings menu.

Incoming messages are left-adjusted and in a (by default yellowish) color. Outgoing messages are right-adjusted and in a (by default blue-ish) color.

If the most recent message is sent/received on a new date, the date is shown before the message.

If a message arrives to a conversation whose tab is not selected, a little red dot is added to the tab label, to indicate unread messages.

If a message arrives when the Converse window is not the focused/active window, an attempt is made to "bounce" the application icon (e.g. in the Dock, on macOS).

The Conversation menu allows clearing the current conversation tab, removing it altogether, and removing the current destination from the destination input drop-down menu.

To clear all conversation histories, use `Clear all conversations` in the Settings menu. 
To remove all conversation tabs, use `Remove all conversations` in the Settings menu.

If the `Save/restore messages between sessions` is on, messages are automatically saved to a file when received and sent, and restored when Converse is restarted. You can clear the file with saved messages using the `Clear stored messages` menu item, and select the file to store them in using `Set message store file...`.

#### Destination online status

Unless disabled, the online status of destinations is periodically checked in the background. The status is indicated using colored dots in the conversation tabs. 
- a green dot indicates that the destination is active (not idle for very long),
- a yellow dot indicates that the destination is idle (not active, but not idle for VERY long),
- a black dot indicates that the destination is away (idle for a very long time),
- a grey dot indicates that the destination user is not online, but the host is up,
- no dot means that the destination host seems to be down, or its status is unknown.
  
When your screen is locked, checking for online status is paused (to reduce network traffic and load on hosts), and the dots are removed. When you unlock your screen, the online status is again monitored (after a short while) and the dots re-appear. Checking if your screen is locked is done every minute. If you are running something else than macOS, let me know how to check if your screen is locked so it can be implemented.

To manually refresh the online status, use `Refresh online status` in the Converse menu. To stop monitoring online status, disable the `Enable destination online checks` option in the Settings menu.

You can change interval between online checks (default 5 minutes), the idle/away time limits (default 10/120 minutes), and the colors of idle/away dots in the Settings menu.

### Destination input

The destination can be input in this part, using the syntax `user@host`, where `user` is the remote userid and `host` is the name of a Chaosnet host. If the destination is new, it will be saved and can be selected from the drop-down menu. Selecting a destination here also selects the matching Conversation tab.

If a "shortname" or alias for the `host` is used, an attempt is made to expand the shortname into a fully qualified domain name. E.g., if `victor@up` is input, it will/should be expanded to `victor@UP.dfUpdate.SE`.

The destination list can be edited using the `Edit destination menu` menu item, and cleared by the `Clear destination menu`.
To remove the currently selected destination from the list, use `Remove current destination` from the Conversation menu.

You can edit the settings for the DNS server accepting Chaosnet-class queries, and the domain search list, in the Settings menu. The default domain search list is your local domain (i.e. the domain of your local Chaosnet host) followed by "Chaosnet.net". (You most likely do not want to change the DNS server from the default, "DNS.Chaosnet.net", since very very few DNS servers are configured to handle Chaosnet-class queries in a useful way.)

### Message Input

The message to be sent is input here. You can send it by pressing [Control-S] (or [Command-S] on macOS), or using the `Send message` menu item.

The message input field can be one-line (the default), or multi-line, depending on the `Use multi-line messages` setting.  When using one-line input, [Enter] also sends the message.

For multi-line messages, you can set the number of lines in the input window with the `Set lines in multi-line message input` setting.

Messages are restricted to ASCII, for compatibility with older systems.

## Settings
**This section needs updating, but items are, hopefully, self-evident.**

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

Requirements: dnspython, pyqt6, nocasedict. All three can be installed with `pip3 install ...`

Doing `make` in the `tools` subdirectory uses [pyinstaller](https://pyinstaller.org/en/stable/) to produce an app from the python sources. If `pip3 install PyInstaller` doesn't put pyinstaller in your `PATH`, please see a comment in [Makefile](Makefile).

## Future plans/features

- [ ] Sending the message should be done in a separate thread, so it can be interrupted/cancelled if it takes too long time.
- [ ] There should be a sounds menu for selecting sounds for incoming/outgoing/alert messages.
- [ ] You may want to set an auto-reply (if you go AFK), and there should be a setting for at what idle time the auto-reply is sent. *(And it should ideally be sent if your screen is locked, too.) (Perhaps the auto-reply should be implemented using a CLS packet with the message, to avoid auto-auto-replies?)*
- [ ] There could be a Dock icon counter for unseen incoming messages, on macOS.
- [ ] You could dream of a "group chat" setting, which automatically sends messages to a set of destinations. *Need to handle replies sensibly though (so they go to all in the group). Probably a new/compatible protocol for group handling, which uses SEND for transport?*
- [ ] If the dnspython requirement is awkward, it could be replaced by a HOSTAB client, but it might not be as fast?

Let me know if you (want (me) to) implement any of this, or if you have more ideas!

## Known issues

- An attempt at setting an icon for the menu items for editing colors, but this does not always have effect in PyQt6 on macOS. *Probably depends on installation issues, it works on one of my macs.*
- QSoundEffect doesn't seem to work in either PyQt6 or PySide6, on my Mac.
- Sound effects are only really tested/implemented under macOS, using `afplay`.
- Screen locking is only detected on macOS.
- The default file name for storing messages is probably not portable outside Linux/macOS OSs.
