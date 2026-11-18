# GreyTab 0.3.1 validation

The 0.3.1 release focuses on recorded HTTP traffic, message inspection, Repeater editing and HAR export. It uses the pinned Linux x86_64 runtime with Chromium 156.0.8078.79 and Python 3.13.18.

The focused browser suite verifies local HTTP and HTTPS capture, stable paging and live pause, search across saved notes, repeated query fields, saved annotations, regex errors, links from Site Map into History, HAR downloads spanning multiple batches and preservation of a Repeater draft during a send. It captures all ten workspace views at 320, 380, 768 and 1440 pixels plus the populated Inspector.

The History tests exercise SQLite filters, pagination and site map aggregation with synthetic data. HAR regressions check entries across a batch boundary, repeated and blank query values, and UTF-8 request body sizes. See [Testing](TESTING.md) for the commands and [Usage](USAGE.md#limits) for preview and export limits.

The package was installed from scratch in a path containing spaces and reinstalled without overwriting saved fixture data. Two consecutive launches of the installed backend passed, and parallel launches were rejected while its ports were listening.

This validation concerns GreyTab's own workflows and layout. Comparative scanner accuracy and interoperability with Burp Suite extensions fall outside its scope.
