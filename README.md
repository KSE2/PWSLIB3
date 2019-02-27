# PWSLIB3
Java module to handle Password Safe encrypted databases in all known formats

Current status: RELEASE 2-9-0

Release date: 27 Feb. 2019

Platform: Java 1.8

Distribution License: BSD-like (2-clause, proprietary)

Contributions: strong encryption software by Cryptix Foundation; others

Addresses: local file system, http internet (read-only)

Available Supplements:

-- FTP IO-adapter

Includes package: FTP4J (Sauron Software 2012) distr. under LGPL 2


Release 2-9-0

- added new interface elements (functions) in PwsCipher for encrypting and 
  decrypting of data blocks so that these functions don't return a new byte
  array

- optimised algorithms for reading and writing databases with less demand on 
  heap space
  
- optimised class for cipher mode CFB
- cipher mode CFB can now crypt user data of any length

- using cipher mode CFB for internal veiling of user data

- new platform: Java 1.8 (was 1.6 before)

Release 2-8-1

- maintenance release; optimisations in data complexity

- PwsRawField improved behaviour of cloning

- PwsRawField now allows data direct reference to external block

New Features with 2-7-0

Release 2-7-0

- major release; interface additions and behaviour changes

New Features with 2-7-0

- introduction of a multi-field (3) sort facility in OrderedRecordList including sort
  directions ASCENDING and DESCENDING. Enum DefaultRecordWrapper.SortField describes
  available datafields as sort options.

- PwsRecordList.merge has a new return type of 3 record lists which make traceable what
  has happened during merge.

- the logical database name is made more easily available through new method 
  PwsFile.getDatabaseName().

- introduction of a time-stamp value for PwsFile representing a real or assumed
  time marker of the external state (used for detecting file save conflicts).

- minor corrections; PwsRecordList made Iterable

New Features with 2-6-0

- for files of version 3: fixed conversion from user input character string to primary 
  file access key material to UTF-8 encoding. Password Safe V3 format definition was 
  unspecific to this point and hitherto practice relied on the JVM default which basically 
  is locale and OS specific.
  In order to standardise file access among varying locations of use, this step was required.
  In consequence of this modification, failing file access may occur if characters outside 
  of ASCII have been used as key material. In this case the file should be opened in a previous
  version of this software and the access key modified to a key which contains only ASCII 
  characters. This modified file should be able to open under new conditions (2-6 and later). 
  There is no other solution.

- Extra Fields in PwsRecord (record data field types outside of the Password Safe data canon)
  are now stored encrypted in memory; was cleartext before. 

- the standard (internal) cipher used and provided by PWSLIB package is now Twofish ECB 
  (was Blowfish before).

- performance of crypting and file reading routines has been improved.


Bug Fixes with 2-5-1

- corrected a bug in CryptoRandom that reduced the value range of nextInt(int)
  and appeared to prefer negative values in nextLong()
- corrected a bug in OrderedRecordList which falsely kept some updated old record
  states (doubles) after reindex when record title has changed

New Features with 2-5-0

- all parts were overhauled for standardised coding style and improved
  Javadoc descriptions
- PwsRecordList was particularly overhauled for increased efficiency and
  performance
- added methods and constructors in PwsRecordList, PwsFile and ContextFile
  to improve usability
- OrderedRecordList restructured and now features a record filtering tool
- FilterRecordList removed (functionality replaced by OrderedRecordList)
- FTP application adapter rewritten for use of external library ftp4j-1.7.2.jar
  by Sauron Software, Italy. FTP functionality is offered under LGPL license as
  supplement
- introduced JUnit testing for PwsRecordList and PwsFile
- Log now has an opening for definiing expressions to suppress messages
