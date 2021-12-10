<#
.SYNOPSIS
  The "Get-IPEnrichment" function takes one IP address or an array IP addresses and returns additional information about each of them (such as the PTR Record, WhoIs information, and GeoIP information). 
  
.EXAMPLE
  PS C:\> $Enriched = Get-IPEnrichment -IPAddress 13.108.238.149
  PS C:\> $Enriched

  IPAddress           : 13.108.238.149
  PtrRecord           : smtp06-iad-sp2.mta.salesforce.com
  City                : Washington
  Region              : Washington, D.C.
  Code                : US
  Country             : United States of America
  Continent           : NA
  Org                 : AS14340 Salesforce.com, Inc.
  WhoIsName           : SALESF-3
  RegistrationDate    : 2014-11-18T13:44:13-05:00
  CustomerRef_handle  :
  CustomerRef_name    :
  StartAddress        : 13.108.0.0
  EndAddress          : 13.111.255.255
  CidrLength          : 14
  OrgRef_handle       : SALESF-3
  OrgRef_name         : Salesforce.com, Inc.
  ParentNetRef_handle : NET-13-0-0-0-0
  ParentNetRef_name   : NET13
  UpdateDate          : 2015-02-11T11:37:01-05:00
  OriginAS            : AS14340
  LookupDate          : 2021-03-10


  PS C:\> IPEnrichment 13.108.238.149

  IPAddress           : 13.108.238.149
  PtrRecord           : smtp06-iad-sp2.mta.salesforce.com
  City                : Washington
  Region              : Washington, D.C.
  Code                : US
  Country             : United States of America
  Continent           : NA
  Org                 : AS14340 Salesforce.com, Inc.
  WhoIsName           : SALESF-3
  RegistrationDate    : 2014-11-18T13:44:13-05:00
  CustomerRef_handle  :
  CustomerRef_name    :
  StartAddress        : 13.108.0.0
  EndAddress          : 13.111.255.255
  CidrLength          : 14
  OrgRef_handle       : SALESF-3
  OrgRef_name         : Salesforce.com, Inc.
  ParentNetRef_handle : NET-13-0-0-0-0
  ParentNetRef_name   : NET13
  UpdateDate          : 2015-02-11T11:37:01-05:00
  OriginAS            : AS14340
  LookupDate          : 2021-03-10



  Here we run the function two ways.  First we use the full function name of "Get-IPEnrichment" and we supply a single IP Address as the argument for the "-IPAddress" parameter.  In return, we get various information from GeoIP and WhoIS lookups about the IP Address we supplied.  In the second example we run the function using the built-in alias of "IPEnrichment" and reference the IP Address we want to lookup.  The "-IPAddress" parameter is at position 0, so we don't need to explicitly tell the function that is the parameter we are using; and as you can see, we can the same results as before.  

.NOTES
  Name:  Get-IPEnrichment.ps1
  Author:  Travis Logue
  Version History:  3.1 | 2022-02-08 | Refactored the code so that if a WhoIs / GeoIP lookup has already been done for the array of IP Addresses, those results are reused
  Dependencies: Get-WhoIs.ps1 | Get-GeoIP.ps1 | Get-CountryCodesAndContinents.ps1
  Notes:
  - This had some good info about the [ipaddress] class (though we went with [version] because it allowed us to properly sort / compare IP Address strings):  https://www.itprotoday.com/powershell/working-ipv4-addresses-powershell

  - 2019-12-08 - This is where I learned I could cast the object/property to [version] to properly sort IP Addresses:  https://www.madwithpowershell.com/2016/03/sorting-ip-addresses-in-powershell-part.html


  .
#>
function Get-IPEnrichment {
  [CmdletBinding()]
  [Alias('IPEnrichment')]
  param (
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [string[]]
    $IPAddress
  )
  
  begin {

    # Here we create an array to store the IPAddresses in from the $IPAddress parameter (added in the 'process block')
    $MainIPAddressArray = @()


    # Here we define a function that will be used in the 'end' block below
    function Invoke-IPEnrichmentEngine {
      [CmdletBinding()]
      param (
        [Parameter(Mandatory)]
        [string[]]
        $IPAddresses
      )
      
      $FinalLookupResults = foreach ($EachIP in $IPAddresses) {
    
        $GeoIPResults = Get-GeoIP $EachIP
        $CountryAndContinentResults = Get-CountryCodesAndContinents -CountryCode ($GeoIPResults.Country)
        $WhoIsResults = Get-WhoIs $EachIP
        $LookupDate = Get-Date -Format yyyy-MM-dd
  
        $prop = [ordered]@{
          IPAddress           = $EachIP
          PtrRecord           = $GeoIPResults.hostname
          City                = $GeoIPResults.city
          Region              = $GeoIPResults.region
          Code                = $GeoIPResults.country
          Country             = $CountryAndContinentResults.CountryName
          Continent           = $CountryAndContinentResults.ContinentCode
          Org                 = $GeoIPResults.org
          WhoIsName           = $WhoIsResults.name
          RegistrationDate    = $WhoIsResults.registrationDate
          CustomerRef_handle  = $WhoIsResults.customerRef_handle
          CustomerRef_name    = $WhoIsResults.customerRef_name
          StartAddress        = $WhoIsResults.startAddress
          EndAddress          = $WhoIsResults.endAddress
          CidrLength          = $WhoIsResults.cidrLength
          OrgRef_handle       = $WhoIsResults.orgRef_handle
          OrgRef_name         = $WhoIsResults.orgRef_name
          ParentNetRef_handle = $WhoIsResults.parentNetRef_handle
          ParentNetRef_name   = $WhoIsResults.parentNetRef_name
          UpdateDate          = $WhoIsResults.updateDate
          OriginAS            = $WhoIsResults.originAS
          LookupDate          = $LookupDate
        }
    
        $obj = New-Object -TypeName psobject -Property $prop
        Write-Output $obj
  
      }
  
      Write-Output $FinalLookupResults

    }

  }
  
  process {
    $MainIPAddressArray += $IPAddress
  }
  
  end {

    $IPEnrichmentResults = @()
    $Final = @()
    
    foreach ($IP in $MainIPAddressArray) {
      if ($IPEnrichmentResults.Count -gt 0) {
        $Counter = $IPEnrichmentResults.Count
        $AlreadyFoundInLookupTable = $false
        while ($Counter -ne 0) {
          foreach ($Result in $IPEnrichmentResults) {
            if ([version]$Result.StartAddress -le [version]$IP -and [version]$IP -le [version]$Result.EndAddress) {
              $AlreadyFoundInLookupTable = $true
              $Counter = 0
              $TempObj = $Result.psobject.copy()
              $TempObj.IPAddress = $IP
              $PtrLookup = Resolve-DnsName $IP -Type PTR -ErrorAction SilentlyContinue
              if ($PtrLookup) {
                $TempObj.PtrRecord = $PtrLookup.NameHost
              }
              else {
                $TempObj.PtrRecord = $null
              }
              $Final += $TempObj
              # This will break us out of the "foreach" loop, and back to the "while" loop (which we will also exit because the $Counter = 0)
              break
            }
            else {
              $Counter -= 1
            }
          }

        }
        if ($AlreadyFoundInLookupTable -eq $false) {
          $TempEnrichmentResults = Invoke-IPEnrichmentEngine $IP
          $IPEnrichmentResults += $TempEnrichmentResults
          $Final += $TempEnrichmentResults
        }
      }
      else {
        $TempEnrichmentResults = Invoke-IPEnrichmentEngine $IP
        $IPEnrichmentResults += $TempEnrichmentResults
        $Final += $TempEnrichmentResults
      }
    
    }

    Write-Output $Final

  }
}