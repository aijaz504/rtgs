# RTSP Killer ![](img/logo-small.png)

> Inspired by [Cameradar](https://github.com/Ullaakut/cameradar) and [rtsp_authgrinder.py](https://github.com/Tek-Security-Group/rtsp_authgrinder).

RTSP Killer performs enumeration and bruteforce of the RTSP protocol.

Features:

- Enumerate common streaming routes
- Bruteforce credentials using defaults and most common usernames/passwords
- Supports Basic authentication and Digest authentication (only md5)
- Automatically connects to video streams

# Usage

Scan your host on port 554

```bash
python3 rtsp-killer.py -t 127.0.0.1
```

Scan your host on port 8554 with verbose

```bash
python3 rtsp-killer.py -t 127.0.0.1 -n 8554 -v
```

# Installation

```bash
git clone https://gitlab.com/brn1337/rtsp-killer.git
cd rtsp-killer
pip3 install -r requirements.txt
# optional but recommended
sudo apt install vlc
```

# Demo

![](img/demo1.png)
![](img/demo2.png)

# License

RTSP Killer is licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/?ref=chooser-v1)

```
CC-BY-NC-SA This license requires that reusers give credit to the creator.
It allows reusers to distribute, remix, adapt, and build upon the material in any medium or format, for noncommercial purposes only.
If others modify or adapt the material, they must license the modified material under identical terms.
- Credit must be given to you, the creator.
- Only noncommercial use of your work is permitted.
- Adaptations must be shared under the same terms.
```
