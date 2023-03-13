# I no longer maintain this project, however you can find updated releases here:-  https://github.com/raijutech/absolutePowershell


# absolutePowershell

**Installation**

Copy the com.absolute.api folder to your C:\Program Files (x86)\WindowsPowerShell\Modules directory to make the module available to the entire machine and all users.

In a new powershell console execute *Import-Module com.absolute.api* to add the module to that session.


**Authentication**

Create an authentication token by calling the Set-AbsoluteAuth function.

	Example:  $myAuth =  -apiToken "<Token>" -apiSecret "<Secret>"



**Commands Available**


**Get-Device** - Gets the full api output for that device, max 100 devices per call.  Reponse is an opject so can be used like $response.os.name for example

	Parameters:

	-auth -Authentication token created above
	-DeviceList -List of device ESN's or Serial numbers used to find the devices
	-SerialNumbers -Specifies if the list of devices are serial numbers (default is ENS's)


**Get-ActiveDevices** - gets an array of all active devices.  By defult only collects id, ESN, SystemName, systemManufacturer, systemodel, serial, username, domain, lastConnected UTC

	Parameters:

	-auth -Authentication token created above
	-FieldList -Array of additional fields to collect when the fetch is executed. Use comma to seperate values

	Example: $test = Get-ActiveDevices -authData $myauth -FieldList os.name,os.build


**Invoke-FreezeDevice** - Causes a device freeze

	Parameters:

	-auth -Authentication token created above
	-DeviceList -List of device ESN's or Serial numbers used to find the devices
	-SerialNumbers -Specifies if the list of devices are serial numbers (default is ENS's)
	-RequestName -Name for the Request in the console
	-Passcode - 4 to 8 digit unlock pin
	-MessageName -(Optional) Name of the Message
	-Message -message to disply on the users screen when frozen
	-NotifyeMails -list of email addresses to be sent status updates of the freeze


**Invoke-UnFreezeDevice** - Unfreezes a frozen Device

	Parameters:

	-auth -Authentication token created above
	-DeviceList -List of device ESN's or Serial numbers used to find the devices
	-SerialNumbers -Specifies if the list of devices are serial numbers (default is ENS's)


**Invoke-UnEnrollDevice** - Removes a device permanantly from the Absolute system.

	Parameters:

	-auth -Authentication token created above
	-DeviceList -List of device ESN's or Serial numbers used to find the devices
	-SerialNumbers -Specifies if the list of devices are serial numbers (default is ENS's)



**Get-DeviceCdf** - Creates an object that contains any existing custom defined fields for the device and available CDF's that can be added

	Parameters:

	-auth -Authentication token created above
	-Device -Device ESN's or Serial numbers used to find the device
	-SerialNumber -Specifies if the device is a serial numbers (default is ENS's)


	Methods Available on Object:

	get(<CDF Name>) - Provide the name of the CDF to get, value is returned
	set(<CDF Name>, <CDF Value>) - Name of the CDF to set and the value to set, returns True if sucessfull.  NOTE: Dates are parsed into the correct format for api so you should be ok to use local, best to use mm/dd/yyyy if possible
	available() - Returns a list of available CDF's for account used in Get-DeviceCDF

    

**Set-DeviceCdf** - Updates CDF data into the Absolute plaform, requires the output from a Get-DeviceCdf as an input

	Parameters:

	-auth -Authentication token created above
	-CdfData -Object created from a get-DeviceCDF call.


	**Eample use of Set-DeviceCdf**

	#Create the object
	$myCdf = Get-DeviceCdf -auth <auth> -device "<ESN>"

	#Set as many values as you like
	$myCdf.set("Warranty Start Date", "02/23/2019")
	$myCdf.set("Assigned Username", "Mr Alan, P. India")

	#Save the changes back to the api
	Set-DeviceCdf -auth <auth> -Cdfdata $myCdf


**Convert-UnixDateTime** - Allows for pipeline conversion of Unix timestamp date/time to human readable

	Parameters:
	
	-FieldList -List of field names to convert
	
	**Eample use of Convert-UnixDateTime**
	
	Get-ActiveDevices -auth $abtAuth | Convert-UnixDateTime -FieldList lastConnectedUtc
