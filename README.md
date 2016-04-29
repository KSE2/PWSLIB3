# PWSLIB3
Java module to handle Password Safe encrypted databases in all known formats
Current status: RELEASE 2-5-2
Release date: 30 Apr 2016

Platform: Java 1.6 or higher
Distribution License: BSD-like (2-clause, proprietary)
Contributions: strong encryption software by Cryptix Foundation; others
Addresses: local file system, http internet (read-only)

Available Supplements:
-- FTP IO-adapter
Includes package: FTP4J (Sauron Software 2012) distr. under LGPL 2


Release 2-5-2

- minor adjustments for JPasswords 0-8-0-RC1; upgrade not required.

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
