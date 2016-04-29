KSE PWSLIB 2-5-2

KSE Password Safe V3 Library
README FILE

This package is a stand-alone project distributed under a BSD-like license,
see the license.txt file for details.
It was formerly a part of the JPasswords project (JPWS) which is its first
application (http://jpws.sourceforge.net).

A media related supplement to the core packages is available to support FTP
based file access. This supplement is released under a different license.
Details can be found under "suppl" directory of the project in the download
files.

The file format handled is from open-source project "Password Safe". 
This package contains strong encryption software provided by
The Cryptix Foundation, UK, also under the BSD license, and own development.

Library Platform: Java 1.6 

System Compatibility Format: PWS 3.13 (Password Safe)
Reference Format Documents: formatV3.txt, formatV2.txt, formatV1.txt
Javadoc API documentation available

Release Date: 30 Apr 2016
Text updated: 30 Apr 2016

Available Executable Packages
    pws-engine-kse-2-5-2.jar		Core, BSD-like license
    pws-suppl-ftp-2-5-2.jar		FTP module, LGPL 2

Documentary and Development Packages    
    pws-engine-kse-2-5-2.zip		executables + documentation
    pws-engine-source-2-5-2.zip		source code + libraries + documentation

Release Type
2-5-2 is a release with minor adaptions to service JPasswords 0-8-0-RC1. A general upgrade
for users is not required. See file "changelog.txt" for change history!

-------------------------------

PRODUCT DESCRIPTION

This is a stable, complete library to access, modify and create encryption protected
databases for passwords in the various formats of CounterPane's program "Password Safe"
("PWS" hereafter) by means of Java executable code. 

These are the main features of this software:

a)  Support of a recent security standard of Password Safe files (format version 3.13)

b)  Support of all historical file formats (V2 and V1)

c)  Encryption technology used is Twofish ECB and CBC and SHA256 for V3 files; Blowfish ECB
    and CBC and SHA-1 for V2 and V1 files

d)  Database security level can be set individually by assigning a number of initial 
    calculation loops

e)  Sensible text data, in particular all passwords, are kept encrypted in memory in 
    specialised secure text objects created by this project

f)  Reduced risk from memory analysing attacks through the use of specialized methods to 
    avoid decrypted "waste" material

g)  Abstract IO-interface allows application specific linking of data repositories or 
    IO-channels

h)  A set of canonical record fields allows quick access to commonly used data concerning 
    password entries

i)  Non-canonical, user-defined field types may be introduced to amplify record structure 

j)  Up to 255 header data fields of variable length may be stored on a database generic level
    (e.g. allowing for application environment specific data)

k)  A set of auxiliary classes allows sorted and filtered representation of a PWS file or 
    record list

l)  Event dispatching PWS file class allows smart application design and reaction to content 
    modification

m)  All data is loaded into memory when a file is loaded. The library does not keep open file
    handles outside the load and save methods. Hence maximum processable number of records may
    be limited due to user's runtime environment conditions.

n)  Smartly tailored file socket classes allow user to develop other kind of applications using
    PWS encryption technology


(COMPATIBILITY)

All genuine PWS files (file formats defined by open-source project "Password Safe") up to version V3
should be compatible.

(STATE OF MATURITY)

This version of the library is expected to operate stable in all sections. 

(DOCUMENTATION AND APPLICATION)

Interface of this library is well documented in an API Javadoc html document, available in the
download packages and at the project website. 

