# Logstash Plugin

This is a plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Plugin settings ##

    file_path        - path to CSV file
    ip_column        - CSV column index/column name containing IP's or IP ranges
    ip_field         - event field containg IP to match with the CSV
    map_field        - select and rename columns from the CSV that you want to include in the event
    refresh_interval - Time interval in seconds between checking if CSV has been modified (Default: 300)

## CSV Example ##

Suppose we have the following CSV table which contains information associated to IP's and/or IP ranges:

| Code  | Name   | Priority  | Ip                                            |
|-------|--------|-----------|-----------------------------------------------|
| 12754 | Bogdan | Low       |  192.168.0.0/24 192.168.1.0/24 192.167.10.20  |
| 22132 | Walter | Very High |  192.168.2.0/24 192.168.3.0/24 192.168.4.0/24 |
| 63433 | Jesse  | High      | 192.168.5.0/24                                |
| 16567 | Skylar | Medium    | 10.100.10.100                                 |
| 96032 | Hank   | High      | 192.168.6.0/24                                |

Suppose we have an index with events of this form:

```json
{
    "user" : {
        "ip" : "192.168.2.17"
    }
}
```

We would like to enrich incoming events with information from this CSV based on the IP in the "user.ip" field.

We would then configure the plugin like this:

```
filter {
    csvenrich-ipaddr {
        file_path => "/path/to/CSV/file.csv"
        ip_column => 3
        ip_field => "[user][ip]"
        map_field => { "Code" => "[user][code]" "Name" => "[user][name]" "Priority" => "[user][priority]" }
    }
}
```
Then the previous event would be indexed like this:

```json
{
    "user" : {
        "ip" : "192.168.2.17",
        "code" : "22132",
        "name" : "Walter",
        "priority" : "Very High"
    }
}
```

The IP "192.168.2.17" is in the range "192.168.2.0/24" found on the second line of the CSV (excluding the headers).

The plugin will look at the provided `ip_field` and try to match it with any of the IP's or IP ranges in the `ip_column`, which in this case is 3 (note that column indexing starts from 0, which in this case it's the `Code` column). Instead of the column number, the column header name can also be used (in this case, it would be `ip_column => "Ip"`).

The IP column can contain any number of IP's or IP ranges per row.

## Documentation

Logstash provides infrastructure to automatically generate documentation for this plugin. We use the asciidoc format to write documentation so any comments in the source code will be first converted into asciidoc and then into html. All plugin documentation are placed under one [central location](http://www.elastic.co/guide/en/logstash/current/).

- For formatting code or config example, you can use the asciidoc `[source,ruby]` directive
- For more asciidoc formatting tips, see the excellent reference here https://github.com/elastic/docs#asciidoc-guide

## Need Help?

Need help? Try #logstash on freenode IRC or the https://discuss.elastic.co/c/logstash discussion forum.

## Developing

### 1. Plugin Developement and Testing

#### Code
- To get started, you'll need JRuby with the Bundler gem installed.

- Create a new plugin or clone and existing from the GitHub [logstash-plugins](https://github.com/logstash-plugins) organization. We also provide [example plugins](https://github.com/logstash-plugins?query=example).

- Install dependencies
```sh
bundle install
```

#### Test

- Update your dependencies

```sh
bundle install
```

- Run tests

```sh
bundle exec rspec
```

### 2. Running your unpublished Plugin in Logstash

#### 2.1 Run in a local Logstash clone

- Edit Logstash `Gemfile` and add the local plugin path, for example:
```ruby
gem "logstash-filter-awesome", :path => "/your/local/logstash-filter-awesome"
```
- Install plugin
```sh
bin/logstash-plugin install --no-verify
```
- Run Logstash with your plugin
```sh
bin/logstash -e 'filter {awesome {}}'
```
At this point any modifications to the plugin code will be applied to this local Logstash setup. After modifying the plugin, simply rerun Logstash.

#### 2.2 Run in an installed Logstash

You can use the same **2.1** method to run your plugin in an installed Logstash by editing its `Gemfile` and pointing the `:path` to your local plugin development directory or you can build the gem and install it using:

- Build your plugin gem
```sh
gem build logstash-filter-awesome.gemspec
```
- Install the plugin from the Logstash home
```sh
bin/logstash-plugin install /your/local/plugin/logstash-filter-awesome.gem
```
- Start Logstash and proceed to test the plugin

## Contributing

All contributions are welcome: ideas, patches, documentation, bug reports, complaints, and even something you drew up on a napkin.

Programming is not a required skill. Whatever you've seen about open source and maintainers or community members  saying "send patches or die" - you will not see that here.

It is more important to the community that you are able to contribute.

For more information about contributing, see the [CONTRIBUTING](https://github.com/elastic/logstash/blob/master/CONTRIBUTING.md) file.
