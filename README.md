# basequery-go

basequery-go is a fork of [osquery-go](https://github.com/osquery/osquery-go). This library can be used to write Golang extensions for [basequery](https://github.com/Uptycs/basequery). This library was initially developed by [Kolide](https://www.kolide.com/) and contributed to Osquery foundation.

## Changes
* This implementation supports the additional thrift extension manager method `streamEvents()`.
* `ServerVersion` option is added indicate version of the extension manager server (optional).
* Extension manager client can be retrieved using `GetClient()` method.
