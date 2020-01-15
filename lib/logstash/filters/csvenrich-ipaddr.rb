# encoding: utf-8
require "logstash/filters/base"
require "ipaddr"
require "csv"
require "digest/sha1"

#https://stackoverflow.com/questions/41604782/ruby-ipaddr-find-address-mask
class IPAddr
  def cidr_mask
    case (@family)
    when Socket::AF_INET
      32 - Math.log2((1<<32) - @mask_addr).to_i
    when Socket::AF_INET6
      128 - Math.log2((1<<128) - @mask_addr).to_i
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end
end

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

    #Minimum subnet mask to expand (small masks can generate million of IP's)
    config :minimum_mask, :validate => :number, :default => 19

    public
    def register
        #IP pattern used to scan for IP's in the source column
        @ip_pattern = /\d{,3}\.\d{,3}\.\d{,3}\.\d{,3}\/?\d{,2}/
        #Used to exclude the quad-zero route, if present in the csv (it's too general)
        @next_refresh = Time.now + @refresh_interval
        if not File.size?(@file_path)
            raise "CSV file " + @file_path + " is empty or doesn't exist!"
        end
        reload
    end # def register

    public
    def reload  
        #Save the file hash to compare at the next reload
        file_content = File.read(@file_path)
        @csv_hash = Digest::SHA1.hexdigest(file_content)
        
        @ip_hashmap = Hash.new
        @csv_hashmap = Hash.new
        global_ip_id = 0
        duplicate_ip_total = 0
        duplicate_ip = 0
        
        #Go through CSV, find IP's and expand
        CSV.foreach(@file_path, headers: true, skip_blanks: true, encoding: "utf-8") do |row|
            @csv_hashmap[global_ip_id] = row.to_hash
            duplicate_ip = 0
            if !row[@ip_column].nil?
                #Scan for possible IP ranges (a CSV row can contain multiple IP's or IP ranges)
                array_ranges = row[@ip_column].scan(@ip_pattern)
                array_ranges.each do |ip_range|
                    begin 
                        current_ip_range = IPAddr.new(ip_range)
                    rescue
                        #If the current IP range isn't valid, log a warning and continue
                        @logger.warn? and @logger.warn("Invalid IP " + ip_range.to_s + " found in CSV file " + @file_path)
                    else
                        #Expand just IP's with a reasonably small mask (default: 19), else log a warning
                        if current_ip_range.cidr_mask >= @minimum_mask
                            #Expand the IP range and check if the IP is already hashed
                            current_ip_range.to_range().each() do |ip|
                                #If the IP is not hashed, add it to the IP hashmap 
                                if !@ip_hashmap.has_key?(ip.to_s)
                                    @ip_hashmap[ip.to_s] = global_ip_id   
                                #If the IP is already hashed, log a warning
                                else
                                    duplicate_ip += 1
                                end
                            end
                        else 
                            @logger.warn? and @logger.warn("Found an IP range '" + current_ip_range.to_s + "' with a too broad netmask of " + current_ip_range.cidr_mask.to_s + " (current minimum: " + @minimum_mask.to_s + ") in CSV file " + @file_path)
                        end
                    end      
                end
                #Increment id for the next CSV row
                global_ip_id += 1
            end
            if duplicate_ip > 0
                @logger.warn? and @logger.warn("CSV line (" + row.to_hash.to_s + ") contains " + duplicate_ip.to_s +  + " duplicate IP's from CSV file " + @file_path)
                duplicate_ip_total += duplicate_ip
            end 
        end
        if duplicate_ip_total > 0
            @logger.warn? and @logger.warn("Found " + duplicate_ip_total.to_s + " duplicate IP's in CSV file " + @file_path)  
        end
    end

    public
    def filter(event)
        #Reload the CSV file if the refresh interval has passed, and the CSV file actually changed
        #If the CSV file is missing but a copy is saved into memory, continue processing events but log a warning
        if @next_refresh < Time.now
            if not File.size?(@file_path)
                @logger.warn? and @logger.info("CSV file '" + @file_path + "' no longer exists, but a processed copy is already stored in memory. The plugin will continue to use the stored copy, which will be lost when Logstash is restarted!")
            elsif @csv_hash !=  Digest::SHA1.hexdigest(File.read(@file_path))
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

        #Check if event IP is in the IP hashmap
        if @ip_hashmap.key?(event_ip_field)
            current_ip_id = @ip_hashmap[event_ip_field]
            #Check if the corresponding ID is in the CSV hashmap
            if @csv_hashmap.key?(current_ip_id)
                begin 
                    #Enrich event
                    @map_field.each do |src_field, dest_field|
                        val = @csv_hashmap[current_ip_id][src_field]
                        if !val.nil?
                            event.set(dest_field,val)
                        end
                    end
                rescue 
                    @logger.error? and @logger.error("Exception when trying to map the new fields to the event (Are the fields correct? Is the index mapping correct?)")
                else
                    filter_matched(event)
                end
            end
        end 

    end # def filter
end # class LogStash::Filters::CsvenrichIpaddr
