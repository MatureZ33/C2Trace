README for sttools, v3.5 2025/12/15

INTRODUCTION
============

It is a collection of macro packages historically placed in a bundle 
and maintained by Sigitas Tolušis.

PACKAGES
========

* cuted.sty, v2.10 2025/12/15:  
  – puts some material page width wide at any place on a twocolumn page  
    with existing text reformatted under the inserted material;  
    \preCutedStrip{h... i} and \postCutedStrip{h... i} can be used to add. 
    extra stuff before and after the strip;  
  – switch between onecolumn and twocolumn in the same document 
    with commands: \switchonecolumn and \switchtwocolumn;  
    (2021/10/04): rewrite with new balance algorithm and options;  
    (2025/01/29): bugfix version with improved funcionality;  
    (2025/06/18): adapt to the latest latex kernel;
    (2025/07/14): fix compatibility with the latest LaTeX kernel;
    (2025/10/13): bugfix version;  
    (2025/12/15): bugfix and improved version.  

* cuted2024.sty, v2.5 2025/10/13 (readded for the LaTeX kernel before 2025):  
    (2025/10/13): bugfix version; 
    (2025/12/15): removed from the bundle. 

* floatpag.sty, v2.0 2021/10/04:  
  – sets pagestyle for floats page;  
    (2021/10/04): removed latex209 compatibility; added rotated dblfloat  
                  support;  

* flushend.sty, v4.3 2025/06/18:  
  – balances page in twocolumn mode;  
    (2014/03/03): totally rewritten with new algorithm to support footnotes,  
                  top floats and column break before one line section title;  
    (2014/04/24): bugfix version;  
    (2015/04/08): bugfix version with improved funcionality:  
                  - spreaded or fixed right column height;  
                  - optional old algorithm for backward compatability;  
    (2015/04/14): set debug option off by default; keeplastbox modified;  
    (2016/06/21): bugfix compatibility with luatexja package;  
    (2017/03/27): bugfix version with new options for some checks on/off;  
    (2020/10/14): bugfix development and test;  
    (2020/10/16): bugfix version: modern with noautobase;  
    (2021/10/04): another rewrite with new balance algorithm and options;  
    (2025/02/11): adapt to the latest latex kernel and a new hook;
    (2025/06/18): adapt to the latest latex kernel.  

* marginal.sty, v1.1 2012/05/29:  
  – enlarges room for marginal inserts;  
    (2016/06/28): removed from the bundle.

* midfloat.sty, v1.1 2012/05/29:  
  – inserts onecolumn stuff in twocolumn page;  
  (2025/06/18): removed.

* stabular.sty, v2.3 2025/06/18:  
  – modifies tabular environment;  
    (2014/03/20): removed extra stuff and left only possibility to break  
                  on page boundary;  
                  added tabular variant from array package;  
    (2021/10/04): sync with array bugfix version for tabular;  
    (2025/04/10): code polishing;
    (2025/06/18): adapt to the latest latex kernel.

* stfloats.sty, v3.4 2025/06/18:  
  – enriches floats output mechanism;  
   (2016/06/28): compatibility bugfix with 2015 latexrelease;  
   (2017/03/27): compatibility bugfix with 2017-05-01 latexrelease;  
   (2025/06/18): adapt to the latest latex kernel.

* texsort.sty, v1.1 2012/05/29:  
  – sorts numerical values;  
  TODO: extend (rewrite) to support alphanumerical values  
        for sorting.
  (2025/10/13): removed from the bundle.

INSTALLATION
============

Install in a standard way as any other LaTeX macro package.

AUTHORS/MAINTAINER
==================

* Sigitas Tolušis
* Vytas Statulevičius (floatpag.sty)

DOCUMENTATION
=============

Please see the sttools.pdf for a package list in collection
and <package>.pdf for particular macro package.

LICENSE
=======
```
This work may be distributed and/or modified under the
conditions of the LaTeX Project Public License, either version 1.3
of this license or (at your option) any later version.
The latest version of this license is in
  http://www.latex-project.org/lppl.txt
and version 1.3 or later is part of all distributions of LaTeX
version 2005/12/01 or later.
```


