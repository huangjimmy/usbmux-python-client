# usbmux-python-client
python client of https://cgit.sukimashita.com/usbmuxd.git

# Introduction

This is a usb debugging proxy for use with my version of PonyDebugger (https://github.com/huangjimmy/PonyDebugger)
The original PonyDebugger will require you to install a gateway server called ponyd.
My version of Debugger has an embedded http server so that ponyd is no longer required.

# Prerequisite

- An iMac, Mac mini or Macbook.
- Google Chrome installed

# Installation

If you are using Mac

Run the following command in your terminal
```bash
curl "https://raw.githubusercontent.com/huangjimmy/usbmux-python-client/master/usbdebug.py" -o /usr/local/bin/usbdebug.py 
chmod +x /usr/local/bin/usbdebug.py
```

# Usage
- Launch your app compiled with debugger
- Connect your iPhone/iPad to your Mac with USB
- Know the debugger port of your phone, say 56123
- run the following command in your terminal
```bash
usbdebug.py 56123
```
- Wait a few seconds and then Chrome will open the debugger url for you.
