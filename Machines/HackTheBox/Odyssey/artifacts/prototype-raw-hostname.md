{{ overrides | merge(defaults) | json }}

```{=latex}
\newread\leak
\openin\leak=/etc/hostname
\read\leak to \leakline
\typeout{AEGIS-LEAK:\leakline}
\errmessage{AEGIS-FORCE-DIAGNOSTIC}
\mbox{}
\closein\leak
```
