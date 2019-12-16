# encoding: utf-8
require "logstash/filters/base"
require "ipaddr"
require "csv"
require "digest/sha1"

class LogStash::Filters::CsvenrichIpaddr < LogStash::Filters::Base

    config_name "csvenrich-ipaddr"

    #Path to the CSV file
    config :file_path, :validate => :path, :required => true
    
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
        #IP pattern used to break-up the CSV into multiple rows if there's more than one IP on a row
        @ip_pattern = /\d{,3}\.\d{,3}\.\d{,3}\.\d{,3}\/?\d{,2}/
        @next_refresh = Time.now + @refresh_interval
        if not File.size?(@file_path)
            raise "CSV file " + @file_path + " is empty or doesn't exist!"
        end
        reload
    end # def register

    public
    def reload  
        file_content = File.read(@file_path)
        #Save the file hash to compare at the next reload
        @csv_hash = Digest::SHA1.hexdigest(file_content)
        #Load and parse the CSV file
        file_csv = CSV.parse(file_content, headers: true, skip_blanks: true, encoding: "utf-8")
        #Break every row into multiple rows based on the IP column for easier searching - generates a string
        generated_csv = CSV.generate do |csv|
            #Copy old headers
            csv << file_csv.headers
            file_csv.each do |row|
                #Create rows for every IP or IP range found in the IP column
                if !row[@ip_column].nil?
                    array_ranges = row[@ip_column].scan(@ip_pattern)
                    array_ranges.each do |ip_range|
                        new_row = row
                        new_row[@ip_column] = ip_range
                        csv << new_row.fields
                    end
                end
            end
        end
        #Parse the generated string into a CSV object
        @new_csv = CSV.parse(generated_csv, headers: true, skip_blanks: true, encoding: "utf-8")
    end

    public
    def filter(event)
        #Reload the CSV file if the refresh interval has passed, and the CSV file actually changed
        if @next_refresh < Time.now
            if not File.size?(@file_path)
                raise "CSV file " + @file_path + " is empty or doesn't exist!"
            end
            if @csv_hash !=  Digest::SHA1.hexdigest(File.read(@file_path))
                @logger.info? and @logger.info("CSV file changed. Reloading:" + @file_path)
                reload
            end
            @next_refresh = Time.now + @refresh_interval
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

        if !event_ip_field.nil?
            #Go through every row of the CSV
            @new_csv.each do |row|
                if !row[@ip_column].nil?
                    begin
                        #Check if the current row IP matches with the event IP
                        if IPAddr.new(row[@ip_column]).include?(IPAddr.new(event_ip_field))
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
                        @logger.warn? and @logger.warn("Invalid IP " + row[@ip_column].to_s + " found in CSV file " + @file_path)
                        next
                    end
                end               
            end
        end
    end # def filter
end # class LogStash::Filters::CsvenrichIpaddr
