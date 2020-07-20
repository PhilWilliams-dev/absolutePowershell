##Version 1.71


# Authentication Functions
function SHA256_Hash_Hex_Low_Encode(){
    param(
            $Request
        )
    $sha256 = New-Object System.Security.Cryptography.SHA256Managed
    $hashBytes = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($Request))
    $hashHex = [System.BitConverter]::ToString($hashBytes) -replace '-'
    return $hashHex.ToLower()
}

function HMAC_Hash_Encode_StringSecret(){
    param(
            $Secret,
            $Data
        )
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($Secret)
    $hashBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))
    return $hashBytes
}

function HMAC_Hash_Encode_ByteSecret(){
    param(
            $Secret,
            $Data
        )
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $Secret
    $hashBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))
    return $hashBytes
}

function HMAC_Hash_Hex_Low_Encode(){
    param(
            $Secret,
            $Data
        )
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $Secret
    $hashBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))
    $hashHex = [System.BitConverter]::ToString($hashBytes) -replace '-'
    return $hashHex.ToLower()
}

function UrlEncode($ToBeEncoded){
    
    $ToBeEncoded = $ToBeEncoded -replace "\$","%24"
    $ToBeEncoded = $ToBeEncoded -replace " ", "%20"
    $ToBeEncoded = $ToBeEncoded -replace "'", "%27"
    $ToBeEncoded = $ToBeEncoded -replace "\(", "%28"
    $ToBeEncoded = $ToBeEncoded -replace "\)", "%29"
    $ToBeEncoded = $ToBeEncoded -replace ",", "%2C"

    return $ToBeEncoded
}


#Base Api Request

function Make-request(){
    param(
            $authData,
            $path,
            $query = '',
            $method = 'GET',
            $body = ''
            )

    # VARS
    $HTTPRequestMethod = $method
    $APIHost = $authData.apiHost
    $CanonicalURI = $path
    $CanonicalQueryString = UrlEncode($query)
    $ContentType = 'application/json'
    $date = (Get-Date).ToUniversalTime()
    $date_yyyyMMdd = $date.ToString("yyyyMMdd")
    $date_HHmmss = $date.ToString("HHmmss")
    $XAbsDate = $date_yyyyMMdd + 'T' + $date_HHmmss + 'Z'
    #$XAbsDate = '20190201T124023Z'
    
    # Create a canonical request
    $CanonicalHeaders = "host:" + $APIHost + "`n" + "content-type:" + $ContentType + "`n" + "x-abs-date:" + $XAbsDate
    $RequestPayload = $body
    $HashedPayload = SHA256_Hash_Hex_Low_Encode -Request $RequestPayload
    $CanonicalRequest = $HTTPRequestMethod + "`n" + $CanonicalURI + "`n" + $CanonicalQueryString + "`n" + $CanonicalHeaders + "`n" + $HashedPayload

    # Create a signing string
    $Algorithm = "ABS1-HMAC-SHA-256"
    $RequestDateTime = $XAbsDate
    if($APIHost -eq 'api.us.absolute.com'){$CredentialScope = $date_yyyyMMdd + '/usdc/abs1'} else {$CredentialScope = $date_yyyyMMdd + '/cadc/abs1'}
    $HashedCanonicalRequest = SHA256_Hash_Hex_Low_Encode -Request $CanonicalRequest
    $StringToSign = $Algorithm + "`n" + $RequestDateTime + "`n" + $CredentialScope + "`n" + $HashedCanonicalRequest

    # Create a signing key
    $kSecret = 'ABS1' + $authData.apiSecret
    $kDate = HMAC_Hash_Encode_StringSecret -Secret $kSecret -Data $date_yyyyMMdd
    $kdateTest = [Convert]::ToBase64String($kDate)
    $kSigning = HMAC_Hash_Encode_ByteSecret -Secret $kDate -Data "abs1_request"
    $kSigningTest = [Convert]::ToBase64String($kSigning)

    # Create a signature
    $signature = HMAC_Hash_Hex_Low_Encode -Secret $kSigning -Data $StringToSign

    # Create Headers
    $credential = $authData.apiToken + '/' + $CredentialScope
    $Authorization = $Algorithm + ' Credential=' + $credential + ', SignedHeaders=host;content-type;x-abs-date, Signature=' + $signature
    $header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $header.Add("host",$APIHost)
    $header.Add("Content-Type",$ContentType)
    $header.Add("X-Abs-Date",$XAbsDate)
    $header.Add("Authorization",$Authorization)

    # Make Request

    try{

        if($query -eq ''){
            $url = 'https://' + $APIHost + $CanonicalURI
        }
        else{
            $url = 'https://' + $APIHost + $CanonicalURI + '?' + $query
        }
    
        if($body -eq ''){
            $response = Invoke-RestMethod -Uri $url -Method $method -Header $header
        }
        else{
            $response = Invoke-RestMethod -Uri $url -Method $method -Header $header -Body $body
        }

        return $response
    }
    catch{
        if($_.Exception.Response.StatusCode.value__ -eq 400){return "Device ESN is probably wrong"}
        elseif($_.Exception.Response.StatusCode.value__ -eq 401) {return "API Authenication Failed, correct keys for this device?"}
        else{ return "HTTP Status code: " + $_.Exception.Response.StatusCode.value__ }
    }

}


#Api requests

function Get-ActiveDevices(){
    param(
        $authData,
        [String[]]$FieldList
        )
    $BatchSize=300
    $top = $BatchSize
    $skip=0
        
    #Only collect Active Devices
    $filter = '$filter=agentStatus eq ''A'''

    #Default field list
    $select = '$select=esn,lastConnectedUtc,domain,username,systemName,serial,systemModel,systemManufacturer'

    #Add the optional additional fields
    if($FieldList.Count -gt 0){
    
        foreach($f in $FieldList){

        $select += ',' + $f
        }
    }

    $query = $filter + '&' + $select + '&skip=' + $skip + '&top=' + $top
    
    $devices = Make-request -authData $authData -path '/v2/reporting/devices' -query $query 

    $fetched = $devices.count

    while($fetched -eq $BatchSize){
    #We fetched a batch that is exactly the size requested so there are probably more to get, this is basic pagination
    $skip = $skip + $BatchSize
    $batchDevices = Make-request -authData $authData -path '/v2/reporting/devices' -query $filter + '&' + $select + '&skip=' + $skip + '&top=' $top

    $devices += $batchDevices

    $fetched = $batchDevices.count
    }

    return $devices
}

function Get-DeviceBySerial(){
    param(
        $authData,
        [String[]]$DeviceSerialList
        )
        
    $filter = '$filter='
    foreach($serial in $DeviceSerialList){
    
    $filter += 'serial eq ''' + $serial + ''' or '
    
    }

    $filter = $filter.substring(0,$filter.Length-4)
    
    return Make-request -authData $authData -path '/v2/reporting/devices' -query $filter
}

function Get-DeviceByESN(){
    param(
        $authData,
        [String[]]$esnList)
    
    $filter = '$filter='
    foreach($esn in $esnList){
    
    $filter += 'esn eq ''' + $esn + ''' or '
    
    }

    $filter = $filter.substring(0,$filter.Length-4)
    return Make-request -authData $authData -path '/v2/reporting/devices' -query $filter
}

function Get-DeviceUIDFromESN(){
    param(
        $authData,
        [String[]]$esn)

    return (Get-DeviceByESN -authData $authData -esn $esn).id
}

function Get-DeviceUIDFromserial(){
    param(
        $authData,
        [String[]]$serial)

    return (Get-DeviceBySerial -authData $authData -DeviceSerialList $serial).id
}


#request Body Generation

function MakeFreezeBody(){
    Param(
        [String[]]$uidList,
        [String]$passcode,
        [string]$message,
        [string[]]$emailList,
        [String]$messageName,
        [String]$requestName
    )


   
    $bodyObject = [ordered]@{
        name = $requestName
        message = $message
        messageName = $messageName
        deviceUids = $uidList
        freezeDefinition = @{
            deviceFreezeType = 'OnDemand'
            }
        passcodeDefinition = @{
            option = 'UserDefined'
            passcode = $passcode
        }
        notificationEmails = $emailList
        }

    return ConvertTo-Json $bodyObject -Compress

}

function MakeUnFreezeBody(){
    Param(
            [String[]]$uidList
    )

    $bodyObject = [ordered]@{
        deviceUids = $uidList
        unfreeze = 'true'
    }



    return ConvertTo-Json $bodyObject -Compress

}

function MakeUnenrollBody(){
    Param(
             [String[]]$uidList
        )

        $bodyObject= @()

        $i =0
        foreach($uid in $uidList){
        $bodyObject += @{deviceUid = $uid}
        $i++
        }

    return ConvertTo-Json $bodyObject -Compress
}


#classes

class AbsoluteAuthData{
        [String] $apiToken = "";
        [String] $apiSecret = "";
        [String] $apiHost = ""
}

class CdfData{
    [String] $deviceUid
    [String] $esn
    [CdfValue[]] $cdfValues

    [String]Get([String] $CdfName){

        foreach($v in $this.cdfValues){

        if($v.fieldName -eq $CdfName){
            
            return $v.fieldValue

            }

        }
        
        return ""

    }

    [Bool]Set([String]$CdfName, [String]$CdfValue){

        if($CdfName -eq $null -or $CdfName -eq ''){

          return $false
        }
          
        foreach($v in $this.cdfValues){
            #Loop though the existing Cdf's and update the value if we find it
            if($v.fieldName -eq $CdfName){
            

                if($v.type -eq 'Date'){
                    #Here we deal with a field that needs to be a date, do some validation and return false if it's not

                    if ($cdfValue -as [DateTime])  {
                            #This is a date, now we need to make sure it's in the correct format and update the value

                            [DateTime]$DateValue = $CdfValue -as [DateTime]

                            $v.fieldValue = $DateValue.ToString("MM/dd/yyyy")
                            return $true
                        }
                    elseif($cdfValue -eq ""){
                        #Allow the field to be cleared
                        $v.fieldValue = ""
                        return $true
                        }
                    else{
                        #Date format  was invalid
                        Write-Host("Invald Date Supplied for Date Field")
                        return $false
                        }

                    }

                elseif($v.type -eq 'Dropdown'){
                    #Dealing with Dropdown list types

                    $options = $null

                    foreach($c in $script:AccountCdfData.CdfData){            
                        if($c.Name -eq $CdfName){
                            #Get the list of options from the CDF Definitions
                            $options = $c.dropdowns
                                
                            }
                        }

                    if($options -ne $null){

                        foreach($o in $options){
                                #Make sure that the provided value is one of the options for this field
                                if($o.elementValue -eq $cdfValue){
                                    #Save the value from the available list NOT the one provided as the field is case sensative where the search is not
                                    $v.fieldValue = $o.elementValue
                                    return $true
                                    }
                                if($cdfValue -eq ''){
                                    #Allow the value to be made empty
                                    $v.fieldValue = ""
                                    return $true
                                    }
                                
                            }
                            #We did not find the option specified in the list of available options
                            Write-Host("Value not in list of options for Dropdown")
                            return $false


                        }
                        #This field did not have any options configured in cc
                        Write-Host("This Dropdown Field appears to have not Options to select")
                        return $false
                    }

                else{
                    #Boring old Text fields get handled here
                    $v.fieldValue = $CdfValue
                    return $true

                    }

               
                }
                
                
            }
           


        foreach($v in $script:AccountCdfData.CdfData){
            #We got here because the field name was not in the existing collection, so we go and look in the available CDF's and add the field to the array of values if we find it.
            if($v.Name -eq $CdfName){
            

                if($v.type -eq 'Date'){
                    #Here we deal with a field that needs to be a date, do some validation and return false if it's not

                    if ($cdfValue -as [DateTime])  {
                            #This is a date, now we need to make sure it's in the correct format and add the new value to the array

                            [DateTime]$DateValue = $CdfValue -as [DateTime]

                            $this.cdfValues += [CdfValue]::new($v.Uid, '', $DateValue.ToString("MM/dd/yyyy"), $v.Name, $v.type)
                            return $true
                        }
                    else{
                        Write-Host("Invald Date Supplied for Date Field")
                        return $false
                        }

                    }

                elseif($v.type -eq 'Dropdown'){
                    #Dealing with Dropdown list types


                    $options = $null

                    foreach($c in $script:AccountCdfData.CdfData){            
                        if($c.Name -eq $CdfName){
                            #Get the list of options from the CDF Definitions
                            $options = $c.dropdowns
                                
                            }
                        }

                    if($options -ne $null){

                        foreach($o in $options){
                                #Make sure that the provided value is one of the options for this field
                                if($o.elementValue -eq $cdfValue){
                                    #Save the value from the available list NOT the one provided as the field is case sensative where the search is not
                                    $this.cdfValues += [CdfValue]::new($v.Uid, '', $o.elementValue, $v.Name, $v.type)
                                    return $true
                                    }
                                
                            }
                            #We did not find the option specified in the list of available options
                            Write-Host("Value not in list of options for Dropdown")
                            return $false


                        }
                        #This field did not have any options configured in cc
                        Write-Host("This Dropdown Field appears to have not Options to select")
                        return $false




                    }

                else{
                    #Boring old Text fields get handled here
                    $this.cdfValues += [CdfValue]::new($v.Uid, '', $CdfValue, $v.Name, $v.type)
                    return $true

                    }

                }

            }

        #The requested field value was not found so we return false
        return $false
    }

    [String[]]Available(){
        return $script:AccountCdfData.AvailableCdfs
    }

}

class CdfValue{
    [String] $cdfUid
    [String] $fieldKey
    [String] $fieldValue
    [String] $fieldName
    [String] $type

    CdfValue([String]$cdfUid, [String]$fieldKey, [String]$fieldValue, [String]$fieldName, [String]$type = ''){
        $this.cdfUid = $cdfUid
        $this.fieldKey = $fieldKey
        $this.fieldValue = $fieldValue
        $this.fieldName = $fieldName
        $this.type = $type
    }
 
}

class AccountCdfData{
    [String[]] $AvailableCdfs
    $CdfData
    $auth

    AccountCdfData($auth){
        if($auth.GetType().Name -ne "AbsoluteAuthData") {
        Write-Host "Invalid Authentication object provided" 
        return
        }
        $this.auth = $auth
        $uri = '/v2/cdf/definitions'
        $this.CdfData = Make-request -authData $this.auth -path $uri -method 'GET'

        foreach($f in $this.CdfData){
        
            $this.AvailableCdfs += $f.name
        

        }
    }

}

#Exposed Actions
function Invoke-FreezeDevice(){
    param(
        [Parameter(Mandatory=$true)]$auth,
        [String[]] $DeviceList,
        [Switch] $SerialNumbers,
        [Parameter(Mandatory=$true)][String]$RequestName,
        [Parameter(Mandatory=$true)][String]$Passcode,
        [Parameter(Mandatory=$true)][String]$Message,
        [Parameter(Mandatory=$false)][String]$MessageName = "This is A Freeze Message",
        [Parameter(Mandatory=$true)][String[]]$NotifyeMails
    )

    if($auth.GetType().Name -ne "AbsoluteAuthData") {
        Write-Host "Invalid Authentication object provided" 
        return
        }

    if($DeviceList.Count -eq 0) {
        Write-Host "No Devices specified" 
        return
        }

    if($Passcode.Length -lt 4 -or $Passcode.Length -gt 8){
        Write-Host "Passcode needs to be longer than 4 numbers and larger than 8"
        }
    
    try {0 + $Passcode | Out-Null} 
    catch {
        Write-Host "Passcode must be numeric only"
        return
    }

    if($SerialNumbers){
        $uid = Get-DeviceUIDFromSerial -authData $auth -serial $DeviceList
    }
    else{
        $uid = Get-DeviceUIDFromESN -authData $auth -esn $DeviceList
    }

    $Body = MakeFreezeBody -uidList $uid -passcode $Passcode -message $Message -emailList $NotifiyeMails -messageName $MessageName -requestName $RequestName

    try{
        $response = Make-request -authData $auth -path '/v2/device-freeze/requests' -method 'POST' -body $Body
        return $response
    }
    catch{

    if($_.Exception.Response.StatusCode.value__ -eq 400){ return "Bad Request, device unlicenced or maked as disabled / Stolen"}
    elseif($_.Exception.Response.StatusCode.value__ -eq 401) {return "API Authenication Failed, correct keys for this device?"}
    else{ return "HTTP Status code: " + $_.Exception.Response.StatusCode.value__ }
    }
}

function Invoke-UnFreezeDevice(){
     param(
        [Parameter(Mandatory=$true)]$auth,
        [String[]] $DeviceList,
        [Switch] $SerialNumbers
    )

    if($auth.GetType().Name -ne "AbsoluteAuthData") {
        Write-Host "Invalid Authentication object provided" 
        return
        }

    if($DeviceList.Count -eq 0) {
        Write-Host "No Devices specified" 
        return
        }

    if($SerialNumbers){
        $uid = Get-DeviceUIDFromSerial -authData $auth -serial $DeviceList
    }
    else{
        $uid = Get-DeviceUIDFromESN -authData $auth -esn $DeviceList
    }

    $Body = MakeUnFreezeBody -uidList $uid

    try{
        $response = Make-request -authData $auth -path '/v2/device-freeze/requests' -method 'PUT' -body $Body
        return "OK"
    }
    catch{
        if($_.Exception.Response.StatusCode.value__ -eq 400){ return "Bad Request, device unlicenced or maked as disabled / Stolen"}
        elseif($_.Exception.Response.StatusCode.value__ -eq 401) {return "API Authenication Failed, correct keys for this device?"}
        else{ return "HTTP Status code: " + $_.Exception.Response.StatusCode.value__ }
        }
}

function Invoke-UnEnrollDevice(){
      param(
        [Parameter(Mandatory=$true)]$auth,
        [String[]] $DeviceList,
        [Switch] $SerialNumbers
    )

    if($auth.GetType().Name -ne "AbsoluteAuthData") {
        Write-Host "Invalid Authentication object provided" 
        return
        }

    if($DeviceList.Count -eq 0) {
        Write-Host "No Devices specified" 
        return
        }

    if($SerialNumbers){
        $uid = Get-DeviceUIDFromSerial -authData $auth -serial $DeviceList
    }
    else{
        $uid = Get-DeviceUIDFromESN -authData $auth -esn $DeviceList
    }

    $Body = MakeUnenrollBody -uidList $uid

    try{
        $response = Make-request -authData $auth -path '/v2/device-unenrollment/unenroll' -method 'POST' -body $Body
        return $response
    }
    catch{
        if($_.Exception.Response.StatusCode.value__ -eq 400){ return "Bad Request, device unlicenced or maked as disabled / Stolen"}
        elseif($_.Exception.Response.StatusCode.value__ -eq 401) {return "API Authenication Failed, correct keys for this device?"}
        else{ return "HTTP Status code: " + $_.Exception.Response.StatusCode.value__ }
        }
}

function Get-Device(){
     param(
        [Parameter(Mandatory=$true)]$auth,
        [String[]] $DeviceList,
        [Switch] $SerialNumbers
    )

    if($auth.GetType().Name -ne "AbsoluteAuthData") {
        Write-Host "Invalid Authentication object provided" 
        return
        }

    if($DeviceList.Count -eq 0) {
        Write-Host "No Devices specified" 
        return
        }

    if($DeviceList.Count -gt 100) {
        Write-Host "Too many Devices in a single request, please limit to 100 devices per request"
        return
    }

    try{
        if($SerialNumbers){
            $response = Get-DeviceBySerial -authData $auth -DeviceSerialList $DeviceList
            return $response

        }
        else{
            $response = Get-DeviceByESN -authData $auth -esnList $DeviceList
            return $response
        }

    }
    catch{
        if($_.Exception.Response.StatusCode.value__ -eq 400){ return "Bad Request, device unlicenced or maked as disabled / Stolen"}
        elseif($_.Exception.Response.StatusCode.value__ -eq 401) {return "API Authenication Failed, correct keys for this device?"}
        else{ return "HTTP Status code: " + $_.Exception.Response.StatusCode.value__ }
        }

}

function Set-AbsoluteAuth(){
    param(
        [Parameter(Mandatory=$true)][String]$apiToken = $(Read-Host "Enter API Token: "),
        [Parameter(Mandatory=$true)][String]$apiSecret = $(Read-Host "Enter API Token: "),
        [String]$apiHost = "api.absolute.com"
    )

    $apiAuth = [AbsoluteAuthData]::new()
    
    $apiAuth.apiToken = $apiToken
    $apiAuth.apiSecret = $apiSecret
    $apiAuth.apiHost = $apiHost

    return $apiAuth
}

function Get-DeviceCDF(){
     param(
        [Parameter(Mandatory=$true)]$auth,
        [String] $Device,
        [Switch] $SerialNumber
    )

    if($auth.GetType().Name -ne "AbsoluteAuthData") {
        Write-Host "Invalid Authentication object provided" 
        return
        }

    if($Device.Count -eq 0) {
        Write-Host "No Devices specified" 
        return
        }

    try{
        if($SerialNumber){
            $uid = Get-DeviceUIDFromSerial -authData $auth -serial $Device
            

        }
        else{
            $uid = Get-DeviceUIDFromESN -authData $auth -esn $Device
            
            
        }
        if($script:AccountCdfData -eq $null){
    
            $script:AccountCdfData = [AccountCdfData]::new($auth)
    
        }
        elseif($script:AccountCdfData.auth -ne $auth){
            
            $script:AccountCdfData = [AccountCdfData]::new($auth)

        }

        $uri = '/v2/devices/'+$uid+'/cdf'
        
        $response = Make-request -authData $auth -path $uri -method 'GET'
        
       
        $CdfData = [CdfData]::new()

        $cdfData.deviceUid = $response.deviceUid
        $cdfData.esn = $response.esn
        
        foreach ($c in $response.cdfValues){

        $CdfData.cdfValues += [CdfValue]::new($c.cdfUid, $c.fieldKey, $c.fieldValue, $c.fieldName, $c.type)

        }

        return $CdfData

    }
    catch{
        if($_.Exception.Response.StatusCode.value__ -eq 400){ return "Bad Request, device unlicenced or maked as disabled / Stolen"}
        elseif($_.Exception.Response.StatusCode.value__ -eq 401) {return "API Authenication Failed, correct keys for this device?"}
        else{ return "HTTP Status code: " + $_.Exception.Response.StatusCode.value__ }
        }

}

function Set-DeviceCDF(){
     param(
        [Parameter(Mandatory=$true)]$auth,
        [Parameter(Mandatory=$true)]$CdfData
    )

    if($auth.GetType().Name -ne "AbsoluteAuthData") {
        Write-Host "Invalid Authentication object provided" 
        return
        }

    if(![bool]($CdfData.PSobject.Properties.name -match "deviceUid")){
         Write-Host "CDF Data object does not look right" 
        return
    
    }

    try{
        if($SerialNumber){
            $uid = Get-DeviceUIDFromSerial -authData $auth -serial $Device
            

        }
        else{
            $uid = Get-DeviceUIDFromESN -authData $auth -esn $Device
            
            
        }

        $uid = $CdfData.deviceUid
        $cdfJson = ConvertTo-Json -InputObject $CdfData -Compress
        

        $uri = '/v2/devices/'+$uid+'/cdf'
        
        $response = Make-request -authData $auth -path $uri -method 'PUT' -body $cdfJson
        return $response

    }
    catch{
        if($_.Exception.Response.StatusCode.value__ -eq 400){ return "Bad Request, Something is wrong with the CDF data, possibly a date not in mm/dd/yyyy format ?"}
        elseif($_.Exception.Response.StatusCode.value__ -eq 401) {return "API Authenication Failed, correct keys for this device?"}
        else{ return "HTTP Status code: " + $_.Exception.Response.StatusCode.value__ }
        }

}
