## Description

Python utility scripts for working with a Juniper NetScreen ScreenOS configuration file offline.

* screenos_validation - generates reports for network duplications, address group and book entry duplication, unused address group and book entries, unused service entries, and address book entries for hostnames that do not resolve
* policy_view - print policies offline from a configuration file similar to the cli

## Requirements

* Python >= 2.6

## Caveats for Validation script

* No support for IPv6 entries.
* Does not validate policies for correctness.
* Does not check for duplicate service entries.
* Duplicate network report requires a large screen resolution to view properly.
* Currently reports on address book entries that lie along the same network boundary and are not necessarily identical. e.g. 192.168.1.100/24 ~ 192.168.1.0/25

## Caveats for Policy script

* Does not report on Attack, Schedule, or Traffic shaping options in policies and will always display ---.
* ANSI colors are specific to the BASH shell. Have not tested with others.
* Requires Python >= 2.7 to support the OrderedDict collection or installation of ordereddict (easy_install ordereddict)

## License

Copyright (c) 2011 William Allison

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
