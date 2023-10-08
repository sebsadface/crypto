% Derived from
% https://github.com/GeeLaw/laomian/tree/main/crypto-paper/paper/.laomian
\NeedsTeXFormat{LaTeX2e}[1995/12/01]
\ProvidesClass{homework}[2023/10/01 Homework for CSE 426 Autumn 2023]

\LoadClass[letterpaper,11pt,oneside,onecolumn,final]{article}

% Use LNCS leveling:
\setcounter{secnumdepth}{2}
\def\subsubsection{\@startsection{subsubsection}{3}{\z@}%
{-12\p@ \@plus -4\p@ \@minus -4\p@}%
{-0.5em \@plus -0.22em \@minus -0.1em}%
{\normalfont\normalsize\bfseries\boldmath}}
\def\paragraph{\@startsection{paragraph}{4}{\z@}%
{-12\p@ \@plus -4\p@ \@minus -4\p@}%
{-0.5em \@plus -0.22em \@minus -0.1em}%
{\normalfont\normalsize\itshape}}

% Use LNCS captioning:
\long\def\@makecaption#1#2{%
  \small%
  \vskip\abovecaptionskip%
  \sbox\@tempboxa{{\bfseries #1.} #2}%
  \ifdim \wd\@tempboxa >\hsize%
    {\bfseries #1.} #2\par%
  \else%
    \global \@minipagefalse%
    \hb@xt@\hsize{\hfil\box\@tempboxa\hfil}%
  \fi%
  \vskip\belowcaptionskip%
}

% Page layout.
\RequirePackage[letterpaper,textwidth=6in,textheight=9in,centering]{geometry}

% Page numbers are always enabled for ePrint.
\RequirePackage{lastpage}
\AtBeginDocument{%
  \pagenumbering{arabic}%
  \pagestyle{plain}%
  \def\@oddfoot{\hfil\thepage~/~\pageref*{LastPage}\hfil}
  \let\@evenfoot\@oddfoot
}

\RequirePackage[utf8]{inputenc}
\RequirePackage[english]{babel}
\RequirePackage{xcolor}
\RequirePackage{float,graphicx}
\RequirePackage{tabularx,booktabs,multirow}
\RequirePackage{relsize}

\RequirePackage{afterpage}
\def\clearfloats{\afterpage{\clearpage}}

\RequirePackage[normalem]{ulem}
\RequirePackage[outline]{contour}

\def\ul#1{\uline{#1}}

% Prevent \subparagraph completely.
\let\subparagraph\Laomian@undefined

% Underlines.
\def\ULdepth{0.45ex}
\contourlength{0.32ex}
\def\ul#1{\uline{\phantom{\contour*{white}{#1}}}\llap{\contour*{white}{#1}}}

% Reference names
\def\Figure{Figure}
\def\Equation{Equation}
\def\Section{Section}
\def\Figures{Figures}
\def\Equations{Equations}
\def\Sections{Sections}

\RequirePackage[colorlinks=true,allcolors=blue]{hyperref}

\let\proof\Laomian@undefined
\let\endproof\Laomian@undefined
\RequirePackage{amsfonts,amsmath,amsthm,amssymb,mathtools}
\RequirePackage{bbm,dsfont,mathrsfs,stmaryrd}
\RequirePackage{dashbox}

\def\thmhead@plain#1#2#3{%
  \thmname{#1}\thmnumber{\@ifnotempty{#1}{ }\relax{#2}}%
  \thmnote{ {\the\thm@notefont(#3)}}%
}
\let\thmhead\thmhead@plain

% Undefine these theorem environments as well as the counters.
% They are redefined later.
\def\Laomian@undefine@theorem#1{%
  \expandafter\let\csname #1\endcsname\Laomian@undefined%
  \expandafter\let\csname end#1\endcsname\Laomian@undefined%
  \expandafter\let\csname c@#1\endcsname\Laomian@undefined%
}

\Laomian@undefine@theorem{assumption}
\Laomian@undefine@theorem{claim}
\Laomian@undefine@theorem{conjecture}
\Laomian@undefine@theorem{construction}
\Laomian@undefine@theorem{corollary}
\Laomian@undefine@theorem{definition}
\Laomian@undefine@theorem{lemma}
\Laomian@undefine@theorem{proof}
\Laomian@undefine@theorem{proposition}
\Laomian@undefine@theorem{question}
\Laomian@undefine@theorem{remark}
\Laomian@undefine@theorem{theorem}

% Undefine these theorem environments but keep the counters.
% They are not redefined later.
% Their counters are reset by LNCS and must not be undefined.
\def\Laomian@undefine@theorem#1{%
  \expandafter\let\csname #1\endcsname\Laomian@undefined%
  \expandafter\let\csname end#1\endcsname\Laomian@undefined%
}

\Laomian@undefine@theorem{case}
\Laomian@undefine@theorem{example}
\Laomian@undefine@theorem{exercise}
\Laomian@undefine@theorem{note}
\Laomian@undefine@theorem{problem}
\Laomian@undefine@theorem{property}
\Laomian@undefine@theorem{solution}

\let\Laomian@undefine@theorem\Laomian@undefined

% Modified from amsthm.sty:
\def\th@remark{%
  \thm@headfont{\itshape}%
  \normalfont % body font
  % Use normal spacing.
  % \thm@preskip\topsep \divide\thm@preskip\tw@
  % \thm@postskip\thm@preskip
}

\theoremstyle{remark}
\newtheorem{remark}{Remark}
\newtheorem*{remarks}{Remarks}

\newtheorem*{Laomian@proof}{Proof}
\def\proof{\@ifnextchar[\Laomian@proof@with@name\Laomian@proof@without@name}
\def\Laomian@proof@with@name[#1]{%
  \begingroup%
  \pushQED{\qed}%
  \begin{Laomian@proof}[#1]%
}
\def\Laomian@proof@without@name{%
  \begingroup%
  \pushQED{\qed}%
  \begin{Laomian@proof}%
}
\def\endproof{%
  \popQED%
  \end{Laomian@proof}%
  \endgroup%
}

\theoremstyle{definition}
\newtheorem{definition}{Definition}
\newtheorem{question}{Question}

\theoremstyle{plain}
\newtheorem{conjecture}{Conjecture}
\newtheorem{corollary}{Corollary}
\newtheorem{claim}{Claim}
\newtheorem{lemma}{Lemma}
\newtheorem{proposition}{Proposition}
\newtheorem{theorem}{Theorem}

\let\c@corollary\c@theorem
\let\c@claim\c@theorem
\let\c@lemma\c@theorem
\let\c@proposition\c@theorem

\newtheorem*{Laomian@restated}{\Laomian@restated@name}
\def\restated#1{%
  \begingroup%
  \def\Laomian@restated@name{#1}%
  \begin{Laomian@restated}%
}
\def\endrestated{%
  \end{Laomian@restated}%
  \endgroup%
}

\theoremstyle{definition}
\newtheorem{assumption}{Assumption}
\newtheorem{construction}{Construction}

% Boxes.
\def\dashboxed#1{\dbox{\ensuremath{\displaystyle#1}}}
\definecolor{LaomianLightGray}{RGB}{200,200,200}
\def\grayboxed#1{\fcolorbox{LaomianLightGray}{LaomianLightGray}{\ensuremath{\displaystyle#1}}}

% Greek letters.
\DeclareMathSymbol{\Alpha}{\mathalpha}{operators}{"41}
\DeclareMathSymbol{\Beta}{\mathalpha}{operators}{"42}
\DeclareMathSymbol{\Gamma}{\mathalpha}{operators}{0}
\DeclareMathSymbol{\Delta}{\mathalpha}{operators}{1}
\DeclareMathSymbol{\Epsilon}{\mathalpha}{operators}{"45}
\DeclareMathSymbol{\Zeta}{\mathalpha}{operators}{"5A}
\DeclareMathSymbol{\Eta}{\mathalpha}{operators}{"48}
\DeclareMathSymbol{\Theta}{\mathalpha}{operators}{2}
\DeclareMathSymbol{\Iota}{\mathalpha}{operators}{"49}
\DeclareMathSymbol{\Kappa}{\mathalpha}{operators}{"4B}
\DeclareMathSymbol{\Lambda}{\mathalpha}{operators}{3}
\DeclareMathSymbol{\Mu}{\mathalpha}{operators}{"4D}
\DeclareMathSymbol{\Nu}{\mathalpha}{operators}{"4E}
\DeclareMathSymbol{\Xi}{\mathalpha}{operators}{4}
\DeclareMathSymbol{\Omicron}{\mathalpha}{operators}{"4F}
\DeclareMathSymbol{\Pi}{\mathalpha}{operators}{5}
\DeclareMathSymbol{\Rho}{\mathalpha}{operators}{"50}
\DeclareMathSymbol{\Sigma}{\mathalpha}{operators}{6}
\DeclareMathSymbol{\Tau}{\mathalpha}{operators}{"54}
\DeclareMathSymbol{\Upsilon}{\mathalpha}{operators}{7}
\DeclareMathSymbol{\Phi}{\mathalpha}{operators}{8}
\DeclareMathSymbol{\Chi}{\mathalpha}{operators}{"58}
\DeclareMathSymbol{\Psi}{\mathalpha}{operators}{9}
\DeclareMathSymbol{\Omega}{\mathalpha}{operators}{10}
\DeclareMathSymbol{\omicron}{\mathalpha}{letters}{"6F}

% Long live the orthodox!
\let\Laomian@epsilon@bak\epsilon
\let\epsilon\varepsilon
\let\varepsilon\Laomian@epsilon@bak
\let\Laomian@phi@bak\phi
\let\phi\varphi
\let\varphi\Laomian@phi@bak
\let\emptyset\varnothing
\let\varemptyset\varnothing
\let\nothing\varnothing

% Order symbols.
\def\bigO{\operatorname{O}}
\def\smallo{\operatorname{o}}
\def\bigTheta{\operatorname{\Theta}}
\def\bigOmega{\operatorname{\Omega}}
% \smallomega should be non-italicized, but
% I don't know a satisfactory solution for typesetting
% upright lower-case Greek letters in Computer Modern.
\def\smallomega{\operatorname{\omega}}

\def\cbrt{\sqrt[3]}
\def\vec#1{\boldsymbol{\mathbf{#1}}}
\def\1{{\mathbbm{1}}}

\def\esssup{\operatornamewithlimits{ess\,sup}}
\def\essinf{\operatornamewithlimits{ess\,inf}}
\def\EX{\operatornamewithlimits{\mathbb{E}}}
\def\Var{\operatorname{Var}}
\def\supp{\operatorname{supp}}

\def\approxS{\approx_{\textup{s}}}
\def\iseq{\overset{?}{=}}
\def\defeq{\overset{\mathsmaller{\textup{def}}}{=\joinrel=}}
\def\draws{\overset{\smash{\:_\$}\vphantom{{}_0}}{\leftarrow}}
\def\poly{\operatorname{poly}}
\def\negl{\operatorname{negl}}
\def\concat{{\parallel}}
\def\transpose{{\mathsmaller{\mathsf{T}}}}
\def\bit{{\{0,1\}}}

% 1..26 | % { [char](64 + $_) } | % { "\def\double$_{{\mathbb{$_}}}" }
\def\doubleA{{\mathbb{A}}}
\def\doubleB{{\mathbb{B}}}
\def\doubleC{{\mathbb{C}}}
\def\doubleD{{\mathbb{D}}}
\def\doubleE{{\mathbb{E}}}
\def\doubleF{{\mathbb{F}}}
\def\doubleG{{\mathbb{G}}}
\def\doubleH{{\mathbb{H}}}
\def\doubleI{{\mathbb{I}}}
\def\doubleJ{{\mathbb{J}}}
\def\doubleK{{\mathbb{K}}}
\def\doubleL{{\mathbb{L}}}
\def\doubleM{{\mathbb{M}}}
\def\doubleN{{\mathbb{N}}}
\def\doubleO{{\mathbb{O}}}
\def\doubleP{{\mathbb{P}}}
\def\doubleQ{{\mathbb{Q}}}
\def\doubleR{{\mathbb{R}}}
\def\doubleS{{\mathbb{S}}}
\def\doubleT{{\mathbb{T}}}
\def\doubleU{{\mathbb{U}}}
\def\doubleV{{\mathbb{V}}}
\def\doubleW{{\mathbb{W}}}
\def\doubleX{{\mathbb{X}}}
\def\doubleY{{\mathbb{Y}}}
\def\doubleZ{{\mathbb{Z}}}

% 1..26 | % { [char](64 + $_) } | % { "\def\script$_{{\mathcal{$_}}}" }
\def\scriptA{{\mathcal{A}}}
\def\scriptB{{\mathcal{B}}}
\def\scriptC{{\mathcal{C}}}
\def\scriptD{{\mathcal{D}}}
\def\scriptE{{\mathcal{E}}}
\def\scriptF{{\mathcal{F}}}
\def\scriptG{{\mathcal{G}}}
\def\scriptH{{\mathcal{H}}}
\def\scriptI{{\mathcal{I}}}
\def\scriptJ{{\mathcal{J}}}
\def\scriptK{{\mathcal{K}}}
\def\scriptL{{\mathcal{L}}}
\def\scriptM{{\mathcal{M}}}
\def\scriptN{{\mathcal{N}}}
\def\scriptO{{\mathcal{O}}}
\def\scriptP{{\mathcal{P}}}
\def\scriptQ{{\mathcal{Q}}}
\def\scriptR{{\mathcal{R}}}
\def\scriptS{{\mathcal{S}}}
\def\scriptT{{\mathcal{T}}}
\def\scriptU{{\mathcal{U}}}
\def\scriptV{{\mathcal{V}}}
\def\scriptW{{\mathcal{W}}}
\def\scriptX{{\mathcal{X}}}
\def\scriptY{{\mathcal{Y}}}
\def\scriptZ{{\mathcal{Z}}}

% 1..26 | % { [char](64 + $_) } | % { "\def\cursive$_{{\mathscr{$_}}}" }
\def\cursiveA{{\mathscr{A}}}
\def\cursiveB{{\mathscr{B}}}
\def\cursiveC{{\mathscr{C}}}
\def\cursiveD{{\mathscr{D}}}
\def\cursiveE{{\mathscr{E}}}
\def\cursiveF{{\mathscr{F}}}
\def\cursiveG{{\mathscr{G}}}
\def\cursiveH{{\mathscr{H}}}
\def\cursiveI{{\mathscr{I}}}
\def\cursiveJ{{\mathscr{J}}}
\def\cursiveK{{\mathscr{K}}}
\def\cursiveL{{\mathscr{L}}}
\def\cursiveM{{\mathscr{M}}}
\def\cursiveN{{\mathscr{N}}}
\def\cursiveO{{\mathscr{O}}}
\def\cursiveP{{\mathscr{P}}}
\def\cursiveQ{{\mathscr{Q}}}
\def\cursiveR{{\mathscr{R}}}
\def\cursiveS{{\mathscr{S}}}
\def\cursiveT{{\mathscr{T}}}
\def\cursiveU{{\mathscr{U}}}
\def\cursiveV{{\mathscr{V}}}
\def\cursiveW{{\mathscr{W}}}
\def\cursiveX{{\mathscr{X}}}
\def\cursiveY{{\mathscr{Y}}}
\def\cursiveZ{{\mathscr{Z}}}

% 1..26 | % { [char](64 + $_); [char](96 + $_); } | % { "\def\fraktur$_{{\mathfrak{$_}}}" }
\def\frakturA{{\mathfrak{A}}}
\def\fraktura{{\mathfrak{a}}}
\def\frakturB{{\mathfrak{B}}}
\def\frakturb{{\mathfrak{b}}}
\def\frakturC{{\mathfrak{C}}}
\def\frakturc{{\mathfrak{c}}}
\def\frakturD{{\mathfrak{D}}}
\def\frakturd{{\mathfrak{d}}}
\def\frakturE{{\mathfrak{E}}}
\def\frakture{{\mathfrak{e}}}
\def\frakturF{{\mathfrak{F}}}
\def\frakturf{{\mathfrak{f}}}
\def\frakturG{{\mathfrak{G}}}
\def\frakturg{{\mathfrak{g}}}
\def\frakturH{{\mathfrak{H}}}
\def\frakturh{{\mathfrak{h}}}
\def\frakturI{{\mathfrak{I}}}
\def\frakturi{{\mathfrak{i}}}
\def\frakturJ{{\mathfrak{J}}}
\def\frakturj{{\mathfrak{j}}}
\def\frakturK{{\mathfrak{K}}}
\def\frakturk{{\mathfrak{k}}}
\def\frakturL{{\mathfrak{L}}}
\def\frakturl{{\mathfrak{l}}}
\def\frakturM{{\mathfrak{M}}}
\def\frakturm{{\mathfrak{m}}}
\def\frakturN{{\mathfrak{N}}}
\def\frakturn{{\mathfrak{n}}}
\def\frakturO{{\mathfrak{O}}}
\def\frakturo{{\mathfrak{o}}}
\def\frakturP{{\mathfrak{P}}}
\def\frakturp{{\mathfrak{p}}}
\def\frakturQ{{\mathfrak{Q}}}
\def\frakturq{{\mathfrak{q}}}
\def\frakturR{{\mathfrak{R}}}
\def\frakturr{{\mathfrak{r}}}
\def\frakturS{{\mathfrak{S}}}
\def\frakturs{{\mathfrak{s}}}
\def\frakturT{{\mathfrak{T}}}
\def\frakturt{{\mathfrak{t}}}
\def\frakturU{{\mathfrak{U}}}
\def\frakturu{{\mathfrak{u}}}
\def\frakturV{{\mathfrak{V}}}
\def\frakturv{{\mathfrak{v}}}
\def\frakturW{{\mathfrak{W}}}
\def\frakturw{{\mathfrak{w}}}
\def\frakturX{{\mathfrak{X}}}
\def\frakturx{{\mathfrak{x}}}
\def\frakturY{{\mathfrak{Y}}}
\def\fraktury{{\mathfrak{y}}}
\def\frakturZ{{\mathfrak{Z}}}
\def\frakturz{{\mathfrak{z}}}

% Special formatting for homework.

\def\my@section{\@startsection{section}{1}{\z@}%
{-18\p@ \@plus -4\p@ \@minus -4\p@}%
{12\p@ \@plus 4\p@ \@minus 4\p@}%
{\normalfont\large\bfseries\boldmath
\rightskip=\z@ \@plus 8em\pretolerance=10000\relax\color{boldcolor}}}
\def\my@section@star#1{\my@section*{#1\vskip0.15em\hrule}}
\def\my@section@nostar#1{\my@section{#1\vskip0.15em\hrule}}
\def\section{\@ifstar\my@section@star\my@section@nostar}
\def\subsection{\@startsection{subsection}{2}{\z@}%
{-18\p@ \@plus -4\p@ \@minus -4\p@}%
{8\p@ \@plus 4\p@ \@minus 4\p@}%
{\normalfont\normalsize\bfseries\boldmath
\rightskip=\z@ \@plus 8em\pretolerance=10000\relax\color{boldcolor}}}
\def\subsubsection{\@startsection{subsubsection}{3}{\z@}%
{-18\p@ \@plus -4\p@ \@minus -4\p@}%
{-0.5em \@plus -0.22em \@minus -0.1em}%
{\normalfont\normalsize\bfseries\boldmath\color{boldcolor}}}
\def\paragraph{\@startsection{paragraph}{4}{\z@}%
{-12\p@ \@plus -4\p@ \@minus -4\p@}%
{-0.5em \@plus -0.22em \@minus -0.1em}%
{\normalfont\normalsize\itshape}}

% Formatting inherited from previous homework files.
\RequirePackage{palatino}
\RequirePackage[sc]{mathpazo}

% Package mathpazo kills our orthodox. Restore it.
\let\Laomian@epsilon@bak\epsilon
\let\epsilon\varepsilon
\let\varepsilon\Laomian@epsilon@bak
\let\Laomian@phi@bak\phi
\let\phi\varphi
\let\varphi\Laomian@phi@bak

% "dvips" makes the processor prefer .eps images,
% which is a feature not used for previous homework files.
% \RequirePackage[dvips]{graphicx}
\RequirePackage{enumerate}
\RequirePackage{pifont}
\RequirePackage{tikz}
\RequirePackage[ruled,vlined]{algorithm2e}
\usetikzlibrary{arrows}

% Somehow \operatorname{\omega} gives "!".
\let\smallomega\omega

\def\labelitemi{-}
\def\labelitemii{$\circ$}

\def\This is #1,
posted on #2 at #3
and due on #4 at #5.
{\definecolor{boldcolor}{rgb}{0.00,0.42,0.52}%
\let\This\my@undefined%
\let\ThisSolution\my@undefined%
\noindent{CSE 426: Cryptography}\hfill\ {University of Washington}\\%
\noindent{Prof.~Stefano Tessaro}\hfill\ {Autumn 2023}\\\smallskip%
\begin{center}%
{\textcolorbf{\LARGE #1}}\\%
\medskip\noindent%
\textcolorbf{Posted:} #2 -- #3\\%
\textcolorbf{Due:} #4 -- #5\\%
(Gradescope submission, instructions will be posted.)%
\end{center}%
}

\def\Task #1 -- #2 (#3 points){\section*{Task #1 -- #2\hfill(#3 points)}}

\def\textcolorbf#1{\textbf{{\color{boldcolor}#1}}}
\def\cbf{\bf\color{boldcolor}}
\def\points#1{\textcolorbf{[#1 points]}}

\def\subtasks{\begin{enumerate}[{\cbf a)}]}
\def\endsubtasks{\end{enumerate}}

\def\my@today{today}
\def\my@date@today{\ifcase\month\or January\or February\or March\or April\or May\or June\or July\or August\or September\or October\or November\or December\fi\ \number\day, \number\year}
\def\my@Task #1 -- #2 (#3 points){\section*{Task #1}\def\my@currenttask{#1}}
\def\my@currenttask{??}
\def\Subtask#1{\subsection*{Subtask \my@currenttask.#1)}}

\def\ThisSolution is for #1 by #2 on #3.
{\definecolor{boldcolor}{rgb}{0.05,0.40,0.90}%
\let\This\my@undefined%
\let\ThisSolution\my@undefined%
\let\Task\my@Task%
\def\my@date{#3}%
\ifx\my@today\my@date%
\let\my@date\my@date@today%
\fi%
\noindent{CSE 426: Cryptography}\hfill\ {University of Washington}\\%
\noindent{Prof.~Stefano Tessaro}\hfill\ {Autumn 2023}\\\smallskip%
\begin{center}%
{\textcolorbf{\LARGE #1}}\\%
\medskip\noindent%
#2\\%
\my@date%
\end{center}%
}