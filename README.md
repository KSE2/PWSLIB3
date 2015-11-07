# PWSLIB3
Java module to handle Password Safe encrypted databases in all known formats
Current status: RELEASE 2-4-0

Platform: Java 1.6 or higher
Distribution License: BSD-like (2-clause, proprietary)
Contributions: strong encryption software by Cryptix Foundation; others
Addresses: local file system, http internet (read-only)

Available Supplements:
-- FTP IO-adapter
Includes package: FTP4J (Sauron Software 2012) distr. under LGPL 2


New Features

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
