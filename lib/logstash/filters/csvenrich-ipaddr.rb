# encoding: utf-8
require "logstash/filters/base"
require "ipaddr"
require "csv"

class LogStash::Filters::CsvenrichIpaddr < LogStash::Filters::Base

    config_name "csvenrich-ipaddr"

    #Path to the CSV file
    config :file_path, :validate => :string, :required => true
    
    #Column containing the IP's (index starting from 0)
    config :ip_column, :validate => :string, :required => true
    
    #Event field containing IP
    config :ip_field, :validate => :string, :required => true
    
    #Columns to add to the event
    config :map_field, :validate => :hash, :default => Hash.new, :required => false
    
    #Refresh interval
    config :refresh_interval, :validate => :number, :default => 300

    public
    def register
        # Add instance variables
        @ip_pattern = /\d{,3}\.\d{,3}\.\d{,3}\.\d{,3}\/?\d{,2}/
        
        if @file_path
            if File.zero?(@file_path)
                raise "CSV is empty"
            end
            @next_refresh = Time.now + @refresh_interval
            raise_exception = true
            reload(raise_exception)
        end
    end # def register

    public
    def reload(raise_exception=false)
        #Load and parse the CSV file. Some CSV's have some hidden characters at the beggining (\xEF\xBB\xBF) which must be removed
        @file_csv = CSV.parse(File.read(@file_path, encoding: "utf-8").sub!("\xEF\xBB\xBF",''), headers: true, skip_blanks: true, encoding: "utf-8")
    end

    public
    def filter(event)
        if @file_path
            if @next_refresh < Time.now
                reload
                @next_refresh = Time.now + @refresh_interval
                print "Reloading CSV file: " + @file_path + "\n"
                @logger.debug? and @logger.debug("Reloading CSV file: " + @file_path + "\n")
            end
        end

        return unless filter?(event)

        #Get IP from the specified field and check it's actually an IP
        event_ip_field = event.get(@ip_field)
        
        begin
            IPAddr.new(event_ip_field)
        rescue
            event.tag('csvenrich_invalid_ip_field')
            return
        end
        
        #if !IPAddress.valid?(event_ip_field)
        #    event.tag('csvenrich_invalid_ip_field')
        #    return
        #end
        
        if !event_ip_field.nil?
            #Go through every row of the CSV
            @file_csv.each do |row|
                if !row[@ip_column].nil?
                    #Scan for IPs and IP ranges
                    array_ranges = row[@ip_column].scan(@ip_pattern)
                    array_ranges.each do |ip_range|
                        #Add row info to the event
                        begin
                            if IPAddr.new(ip_range.strip).include?(IPAddr.new(event_ip_field))
                                @map_field.each do |src_field, dest_field|
                                    val = row[src_field]
                                    if !val.nil?
                                        event.set(dest_field,val)
                                    end
                                end
                                filter_matched(event)    
                            end
                        rescue
                            #Just continue if there's an invalid IP or IP range in the CSV
                            next
                        end
                    end
                end               
            end
        end
    end # def filter
end # class LogStash::Filters::CsvenrichIpaddr
