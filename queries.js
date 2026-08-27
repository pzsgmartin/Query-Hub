const queriesData = [
  {
    "id": 1,
    "title": "Process Creation",
    "platform": "defender",
    "subcategory": "Defender for Endpoint",
    "date": "2026-07-07",
    "description": "Retrieves process creation events within a specified time interval.",
    "query": `let startTime = todatetime("YYYY-MM-DD HH:MM");
let endTime = todatetime("YYYY-MM-DD HH:MM");
let device_name = "DEVICENAME";
DeviceProcessEvents
| where Timestamp between (startTime .. endTime) and DeviceName contains device_name
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FileName, FolderPath, ProcessId, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessId
| sort by Timestamp asc`,
    "tags": ["mde", "timestamp", "process", "creation", "device"]
  },
  {
    "id": 2,
    "title": "File Transfer over Network Shares",
    "platform": "defender",
    "subcategory": "Defender for Endpoint",
    "date": "2026-07-07",
    "description": "Retrieves file transfer events over network shares.",
    "query": `let startTime = todatetime("YYYY-MM-DD HH:MM");
let endTime = todatetime("YYYY-MM-DD HH:MM");
let device_name = "DEVICENAME";
DeviceFileEvents
| where Timestamp between (startTime .. endTime)
| where ActionType == "FileCreated" or ActionType == "FileModified"
| where FolderPath startswith "\\\\"  and DeviceName contains device_name
| project Timestamp, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessAccountName, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, FileName, FolderPath, ActionType
| sort by Timestamp asc`,
    "tags": ["mde", "timestamp", "process", "device", "network", "share"]
  },
  {
    "id": 3,
    "title": "Website Connections",
    "platform": "defender",
    "subcategory": "Defender for Endpoint",
    "date": "2026-07-07",
    "description": "Retrieves website connection events within a specified time interval..",
    "query": `let startTime = todatetime("YYYY-MM-DD HH:MM");
let endTime = todatetime("YYYY-MM-DD HH:MM");
let device_name = "HOSTNAME";
DeviceNetworkEvents
| where isnotempty(RemoteUrl) and DeviceName contains device_name
| where Timestamp between (startTime .. endTime)
| extend VirusTotal = strcat(@"https://www.virustotal.com/gui/domain/", RemoteUrl)
| extend UrlScan = strcat(@"https://urlscan.io/search/#", RemoteUrl)
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, InitiatingProcessFileName, VirusTotal, UrlScan
| sort by Timestamp asc`,
    "tags": ["mde", "timestamp", "connection", "device", "domain", "local2remote"]
  },
    {
    "id": 4,
    "title": "Remote Monitoring and Management (RMM) Tool Execution",
    "platform": "defender",
    "subcategory": "Defender for Endpoint",
    "date": "2026-07-07",
    "description": "Retrieves RMM tool execution events.",
    "query": `let device_name = "HOSTNAME";
let LOLRMM = externaldata(Name:string,Category:string,Description:string,Author:string,Date:datetime,LastModified:datetime,Website:string,Filename:string,OriginalFileName:string,PEDescription:string,Product:string,Privileges:string,Fre::string,Verification:string,SupportedOS:string,Capabilities:string, Vulnerabilities:string,InstallationPaths:string,Artifacts:string,Detections:string,References:string,Acknowledgement:string)[@"https://lolrmm.io/api/rmm_tools.csv"] with (format="csv", ignoreFirstRecord=True);
let ParsedExecutables = LOLRMM
	| distinct InstallationPaths
	| extend FileNames = extract_all(@"\b([a-zA-Z0-9 _-]+\.exe)", InstallationPaths)
	| mv-expand FileNames
	| where isnotempty(FileNames)
	| project FileNames = tolower(FileNames)
	| distinct FileNames;
DeviceNetworkEvents
| where tolower(InitiatingProcessFileName) in (ParsedExecutables)
| where DeviceName contains device_name and ActionType == "ConnectionSuccess"
| project Timestamp, InitiatingProcessAccountName, DeviceName, RemoteIP, RemotePort, RemoteUrl, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc`,
    "tags": ["mde", "timestamp", "process", "device", "remote", "rmm", "execution"]
  },
  {
    "id": 5,
    "title": "Most Logged-in Users",
    "platform": "defender",
    "subcategory": "Defender for Endpoint",
    "date": "2026-07-07",
    "description": "Retrieves the most frequently logged-in users.",
    "query": `DeviceLogonEvents
| where DeviceName has_any ("DEVICENAME1", "DEVICENAME2") 
	and ActionType == "LogonSuccess"
| top-nested of DeviceName by count(), 
	top-nested 1 of AccountName by count()`,
    "tags": ["mde", "timestamp", "user", "device", "signin", "sign-in", "login"]
  },
  {
    "id": 6,
    "title": "User Devices",
    "platform": "defender",
    "subcategory": "Defender for Endpoint",
    "date": "2026-07-07",
    "description": "Retrieves devices used by a specific user.",
    "query": `IdentityInfo
| where AccountUpn has_any ("EMAILADDRESS1", "EMAILADDRESS2")
| project AccountName = tolower(AccountName), AccountUpn
| distinct AccountName, AccountUpn
| join kind=inner (
	DeviceLogonEvents
	| where ActionType == "LogonSuccess"
	| project AccountName = tolower(AccountName), DeviceName
) on AccountName
| top-nested of AccountUpn by count(),
	top-nested 1 of DeviceName by count()`,
    "tags": ["mde", "timestamp", "user", "device", "signin", "sign-in", "login"]
  },
  {
    "id": 6,
    "title": "User Login Baseline",
    "platform": "defender",
    "subcategory": "Defender for Identity",
    "date": "2026-07-07",
    "description": " Retrieves a user login baseline.",
    "query": `EntraIdSignInEvents
| where AccountUpn contains "AccountUpn" and ErrorCode == "0"
// | where IPAddress=="FlaggedIP"
| project Timestamp, IPAddress, Country, DeviceName, ErrorCode, ClientAppUsed, Application, UserAgent
| sort by Timestamp desc
//| summarize count() by Country
//| render piechart`,
    "tags": ["mdi", "timestamp", "signin", "user", "sign-in", "login", "baseline"]
  },
  {
    "id": 7,
    "title": "Email Events",
    "platform": "defender",
    "subcategory": "Defender for Office 365",
    "date": "2026-07-07",
    "description": "Retrieves detailed email events, including attachments, URLs, and clicks.",
    "query": `EmailEvents
| where SenderMailFromDomain contains "SenderDomain"
| extend Action = iff(LatestDeliveryAction != DeliveryAction, strcat(DeliveryAction, ", but later ", LatestDeliveryAction), strcat(DeliveryAction))
| project
	Date = Timestamp,
	Sender = SenderFromAddress,
	Recipient = RecipientEmailAddress,
	Subject,
	NetworkMessageId,
	Action
| join kind=leftouter (
	EmailUrlInfo
	| summarize Links = make_set(Url) by NetworkMessageId
) on NetworkMessageId
| join kind=leftouter (
	EmailAttachmentInfo
	| summarize
	    AttachmentNames = make_set(FileName),
	    AttachmentHashes = make_set(SHA256) 
	    by NetworkMessageId
) on NetworkMessageId
| join kind=leftouter (
	UrlClickEvents
	| where ActionType == "ClickAllowed"
	| summarize Clicked = count() > 0 by NetworkMessageId
) on NetworkMessageId
| extend
	Links = coalesce(Links, dynamic([])),
	AttachmentNames = coalesce(AttachmentNames, dynamic([])),
	AttachmentHashes = coalesce(AttachmentHashes, dynamic([])),
	Clicked = iff(coalesce(Clicked, false) == 0, "Not clicked", "Clicked")
| project-away NetworkMessageId*
| sort by Date asc`,
    "tags": ["mdo", "timestamp", "email", "user"]
  },
  {
    "id": 8,
    "title": "Teams Messages from External Senders",
    "platform": "defender",
    "subcategory": "Defender for Cloud",
    "date": "2026-07-07",
    "description": "Retrieves Teams messages sent by external users.",
    "query": `let ChatMembers = dynamic(["EMAIL@domain.com", "EMAIL1@domain.com", "SENDERADDRESS@domain.com"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
   and ActionType in ("ChatCreated", "UserAccepted")
   and IsExternalUser == 1
| mv-expand Member = RawEventData.Members
| extend MemberUpn = tolower(tostring(Member.UPN))
| where MemberUpn in~ (ChatMembers)
| project Timestamp, ActionType, Application, AccountType, MemberUpn, IPAddress, CountryCode, RawEventData
| sort by Timestamp desc`,
    "tags": ["mdc", "timestamp", "teams", "user", "external"]
  },
  {
    "id": 9,
    "title": "User Device Login Events",
    "platform": "crowdstrike",
    "subcategory": "CrowdStrike Falcon",
    "date": "2026-07-07",
    "description": "Retrieves user login events on a device.",
    "query": `| #event_simpleName="UserLogon" 
| user.name =?user.name
| in(field="ComputerName", values=[HOSTNAME])
| table([@timestamp, #event_simpleName, ComputerName, LocalIP, AuthenticationPackage, UserName, source.ip])`,
    "tags": ["cs", "timestamp", "signin", "user", "login", "sign-in"]
  },
  {
    "id": 10,
    "title": "File Write Events (with process tree)",
    "platform": "crowdstrike",
    "subcategory": "CrowdStrike Falcon",
    "date": "2026-07-07",
    "description": "Retrieves file write events on a single endpoint, including process tree information.",
    "query": `| #event_simpleName = /Written/i
| ComputerName =?CompterName
| "Process Tree" := format("[🔗](/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&pid=pid:%s:%s)", field=[aid, ContextProcessId, aid, ContextProcessId])
| table([@timestamp, #event_simpleName, "Process Tree", ComputerName, TargetFileName, ContextBaseFileName, ContextProcessId, ContextImageFileName])
//| groupBy([FileName, ContextImageFileName])`,
    "tags": ["cs", "timestamp", "write", "device", "written"]
  },
  {
    "id": 11,
    "title": "Process Creation (with process tree)",
    "platform": "crowdstrike",
    "subcategory": "CrowdStrike Falcon",
    "date": "2026-07-07",
    "description": "Retrieves process creation events within a specified time interval.",
    "query": `#repo="base_sensor" #event_simpleName="ProcessRollup2" event_platform="Win"
| ComputerName =?CompterName
| "Process Tree" := format("[🔗](/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&pid=pid:%s:%s)", field=[aid, TargetProcessId, aid, TargetProcessId])
| table([@timestamp, #event_simpleName, "Process Tree", ComputerName, LocalIP, UserName, Name, Group, FileName, ImageFileName, OriginalFilename, CommandLine, ParentBaseFileName, GrandParentBaseFileName, SHA256HashData, TargetProcessId, aid, UserSid], limit=max)`,
    "tags": ["cs", "timestamp", "process", "device"]
  },
  {
    "id": 12,
    "title": "Remote Monitoring and Management (RMM) Tool Execution",
    "platform": "crowdstrike",
    "subcategory": "CrowdStrike Falcon",
    "date": "2026-07-07",
    "description": "Retrieves RMM tool execution events.",
    "query": `#repo="base_sensor" #event_simpleName="ProcessRollup2" event_platform="Win"
| Tags=/\b(?<tag_value>2133095507[5-6][0-9]{4})\b/
| ComputerName =?ComputerName
| match(file="falcon/ngsiem-content/application_classification_tags.csv", field=[tag_value], column=[TagValue], include=[Name, Group])
| Group = "RemoteMonitoringAndManagement"
| "Process Graph" := format("[🔗](/graphs/process-explorer/graph?id=pid:%s:%s&investigate=true&pid=pid:%s:%s)", field=[aid, TargetProcessId, aid, TargetProcessId])
| table([@timestamp, #event_simpleName, "Process Graph", ComputerName, LocalIP, UserName, Name, Group, FileName, ImageFileName, OriginalFilename, CommandLine, ParentBaseFileName, GrandParentBaseFileName, SHA256HashData, TargetProcessId, aid, UserSid], limit=max)
| rename([
	["Name","AppName"],
	["Group","AppCategory"]
])`,
    "tags": ["cs", "timestamp", "process", "device", "remote", "rmm"]
  },
  {
    "id": 13,
    "title": "Missing Log Classification",
    "platform": "crowdstrike",
    "subcategory": "LogScale",
    "date": "2026-07-07",
    "description": "Retrieves log source outages.",
    "query": `$missing_logs_classification()
| tsec.logsource=/Vendor: paloalto Module: null/i`,
    "tags": ["cs", "missing", "logsource"]
  },
  {
    "id": 14,
    "title": "Exclusion Creation",
    "platform": "crowdstrike",
    "subcategory": "LogScale",
    "date": "2026-07-07",
    "description": "Helper query to create an exclusion in LogScale.",
    "query": `| $dtsec_preprocessing()
| join({ 
	@id=?AlertID AND @trigger.name=/RULEID/i
| splitString(alert.event_ids, by="\n", as=alert.id) 
| drop([alert.event_ids, @rawstring]) 
| rename(@id, as=alert.id) 
| split(alert.id) 
}, repo=alerts, field=@id, key=alert.id, include=[@trigger.name, alert.id])`,
    "tags": ["cs", "filtering", "exclusion", "tuning", "finetune", "finetuning"]
  },
  {
    "id": 15,
    "title": "General Event Search",
    "platform": "qradar",
    "subcategory": "QRadar",
    "date": "2026-07-07",
    "description": "Retrieves events in general events.",
    "query": `SELECT
	QIDNAME(QID) as 'Event Name',
	LOGSOURCENAME(logsourceid) as 'Log Source',
	DATEFORMAT(startTime,'YYYY-MM-dd hh:mm') as 'Start Time',
	CATEGORYNAME(category) as 'Low Level Category',
	sourceip as 'Source IP',
	sourceport as 'Source Port',
	destinationip as 'Destination IP',
	destinationport as 'Destination Port',
	username as 'Username'
FROM events
WHERE ….
/*START 'YYYY-MM-DD HH:MM'
STOP 'YYYY-MM-DD HH:MM'*/
/*LAST 1 HOURS*/`,
    "tags": ["qradar", "general", "event"]
  },
  {
    "id": 16,
    "title": "Account Changes",
    "platform": "qradar",
    "subcategory": "QRadar",
    "date": "2026-07-07",
    "description": "Retrieves user-related changes.",
    "query": `SELECT 
	DATEFORMAT(startTime,'YYYY-MM-dd hh:mm') as 'Start Time',
	QIDNAME(qid) as 'Event Name',
	"userName" as 'Initiator username',
	"Target Username" as 'Target Username',
	logsourcename(logSourceId) as 'Log Source' 
FROM events 
WHERE qidEventId IN (4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4731, 4732, 4733, 4734, 4735, 4737, 4738, 4740, 4741, 4742, 4743, 4751, 4752, 4753, 4756, 4757, 4767, 4781) 
AND "Target Username" ILIKE '%AccountName%'
ORDER BY startTime DESC 
/*START 'YYYY-MM-DD HH:MM'
STOP  'YYYY-MM-DD HH:MM'*/
/*LAST 1 HOURS*/`,
    "tags": ["qradar", "account", "user", "change"]
  },
  {
    "id": 17,
    "title": "Process Creation",
    "platform": "qradar",
    "subcategory": "QRadar",
    "date": "2026-07-07",
    "description": "Retrieves process creation events within a specified time interval.",
    "query": `SELECT
	DATEFORMAT(startTime,'YYYY-MM-dd hh:mm') as 'Start Time',
	"username",
	"Process Path",
	"Process Name",
	"Command",
	"Process ID",
	"Parent Process Path",
	"Parent Process Name",
	"Parent Process ID"
FROM events
WHERE qidEventId = 4688 AND logSourceId = LogSourceID
/*START 'YYYY-MM-DD HH:MM'
STOP  'YYYY-MM-DD HH:MM'*/
/*LAST 1 HOURS*/`,
    "tags": ["qradar", "process", "device", "execution", "creation"]
  },
  {
    "id": 18,
    "title": "Scheduled Task Creation Events",
    "platform": "qradar",
    "subcategory": "QRadar",
    "date": "2026-07-07",
    "description": "Retrieves scheduled task creation events on a single device.",
    "query": `SELECT
	QIDNAME(qid) as 'Event Name',
	DATEFORMAT(startTime,'YYYY-MM-dd hh:mm') as 'Start Time',
	username as 'Username',
	"TaskCommand" as 'Task Command',
	"CommandArgument" as 'Command Argument',
	"Task Name"
FROM events
WHERE qideventid IN (4698, 4702) AND logSourceId = LogSourceID
/*START 'YYYY-MM-DD HH:MM'
STOP  'YYYY-MM-DD HH:MM'*/
/*LAST 1 HOURS*/`,
    "tags": ["qradar", "task", "scheduled", "create", "creation"]
  },
  {
    "id": 19,
    "title": "VPN Authentication Locations",
    "platform": "qradar",
    "subcategory": "QRadar",
    "date": "2026-07-07",
    "description": "Retrieves VPN authentication events, grouped by source country.",
    "query": `SELECT 
	"userName" as 'Username',
	/*'USERNAMEHERE' as 'Deobfuscated Username',*/
	logsourcename(logSourceId) as 'Log Source',
	GEO::LOOKUP_TEXT(sourceIP, 'country_name') as 'Country Name',
	COUNT(sourceIP) as 'Event Count',
	MIN(DATEFORMAT(startTime,'YYYY-MM-dd hh:mm')) as 'First Event Time'
FROM events 
WHERE qidEventId in (113039, 722051, 722023, 722033, 722032, 'tunnel-up', 'User-Session-Created', 'Log In') AND "userName" ILIKE '%Username%'
GROUP BY "userName", logsourcename(logSourceId), GEO::LOOKUP_TEXT(sourceIP, 'country_name')
LAST 30 DAYS`,
    "tags": ["qradar", "vpn", "authentication", "auth", "signin", "sign-in", "login"]
  },
  {
    "id": 20,
    "title": "Inbound/Outbound RDP Traffic",
    "platform": "darktrace",
    "subcategory": "DarkTrace",
    "date": "2026-07-07",
    "description": "Retrieves RDP traffic.",
    "query": `@fields.source_ip: "SOURCEIP" AND @fields.dest_ip:"DESTINATIONIP" AND @fields.dest_port:"3389"`,
    "tags": ["darktrace", "remote", "rdp"]
  },
  {
    "id": 21,
    "title": "SMB Traffic",
    "platform": "darktrace",
    "subcategory": "DarkTrace",
    "date": "2026-07-07",
    "description": "Retrieves SMB network traffic.",
    "query": `@fields.source_ip:"SOOURCEIP" AND @fields.dest_ip:"DESTINATIONIP" AND @fields.dest_port:"445" AND @fields.msg:"*sharename*"`,
    "tags": ["darktrace", "smb"]
  },
  {
    "id": 21,
    "title": "ICS Activities",
    "platform": "darktrace",
    "subcategory": "DarkTrace",
    "date": "2026-07-07",
    "description": "Retrieves ICS activities classified by DarkTrace.",
    "query": `@fields.source_ip:"SOURCEIP" AND @fields.dest_ip:"DESTINATIONIP" AND @fields.note:"ICS::Read/ICS::Write/ICS::Reprogram/ICS::Action/ICS::Login"`,
    "tags": ["darktrace", "ics", "ot", "command"]
  },
   {
    "id": 21,
    "title": "DNS Requests",
    "platform": "crowdstrike",
    "subcategory": "CrowdStrike",
    "date": "2026-07-08",
    "description": "Retrieves DNS requests.",
    "query": `| ComputerName =?CompterName
| "#event_simpleName" = DnsRequest
| "Process Tree" := format("[🔗](/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&pid=pid:%s:%s)", field=[aid, ContextProcessId, aid, ContextProcessId])
| table([@timestamp, source.ip, ComputerName, "Process Tree", ContextBaseFileName, DomainName, IP4Records, IP6Records])`,
    "tags": ["cs", "endpoint", "dns", "request"]
  },
  {
    "id": 22,
    "title": "USB Device Connections",
    "platform": "crowdstrike",
    "subcategory": "CrowdStrike",
    "date": "2026-07-10",
    "description": "Returns all connected and disconnected USB devices.",
    "query": `| in(field="#event_simpleName", values=["DcUsbDeviceDisconnected", "DcUsbDeviceConnected"])
| ComputerName =?CompterName
| rename([[ComputerName,"Hostname"],[DevicePropertyClassName,"Connection Type"],[DeviceManufacturer,Manufacturer],[DeviceProduct,"Product Name"], [DevicePropertyDeviceDescription,Description], [DevicePropertyClassGuid,GUID],[DeviceInstanceId,"Device ID"]])
| select([@timestamp, #event_simpleName, "Hostname", "Connection Type",Manufacturer, "Product Name", Description, GUID])`,
    "tags": ["cs", "endpoint", "usb", "connection"]
  },
  {
    "id": 23,
    "title": "Calculate Last Windows Boot Time",
    "platform": "crowdstrike",
    "subcategory": "CrowdStrike",
    "date": "2026-07-10",
    "description": "Checks when the host was last rebooted.",
    "query": `#event_simpleName=AgentOnline event_platform=Win  
| ComputerName =?CompterName
| groupBy([ComputerName], function=([selectLast([BaseTime])]))
| LastReboot_milli:=(BaseTime/1000*1024)+978307200
| round("LastReboot_milli")
| LastRebootAgo:=now()-(LastReboot_milli*1000)
| formatDuration("LastRebootAgo", precision=2)
| LastReboot:=formatTime(format="%F %T %Z", field="LastReboot_milli")`,
    "tags": ["cs", "endpoint", "reboot"]
  },
  {
    "id": 24,
    "title": "List of links opened from Outlook",
    "platform": "crowdstrike",
    "subcategory": "CrowdStrike",
    "date": "2026-07-10",
    "description": "List links opened from Outlook.",
    "query": `#event_simpleName=ProcessRollup2 
| ComputerName=?ComputerName ImageFileName=/\\outlook\.exe/i
| regex("(?<FileName>[^\\/|\\\\]*)$", field=ImageFileName, strict=false)
| join(
    {
      #event_simpleName=ProcessRollup2 ImageFileName=/(chrome|firefox|iexplore)\.exe/i
      | MD5:=MD5HashData | ImageFileName=/(\/|\\)(?<ChildFileName>\w*\.?\w*)$/ 
      | ChildCLI:=CommandLine
    }, 
    key=ParentProcessId, field=TargetProcessId, include=[MD5, ChildFileName, ChildCLI]
  ) 
| groupBy([aid, FileName, CommandLine, ChildFileName, ChildCLI, MD5], limit=max)`,
    "tags": ["cs", "endpoint", "outlook", "connection"]
  },
  {
    "id": 24,
    "title": "USB Device Connections",
    "platform": "defender",
    "subcategory": "Defender for Endpoint",
    "date": "2026-07-10",
    "description": "Returns all connected and disconnected USB devices.",
    "query": `let device_name = "DEVICENAME";
DeviceEvents
| where ActionType == "UsbDriveMounted" and DeviceName contains device_name
| extend ParsedFields = parse_json(AdditionalFields)
| project Timestamp, DeviceName, InitiatingProcessAccountName, 
          DriveLetter = ParsedFields.DriveLetter, 
          SerialNumber = ParsedFields.SerialNumber, 
          ProductName = ParsedFields.ProductName, 
          Manufacturer = ParsedFields.Manufacturer
| order by Timestamp desc`,
    "tags": ["defender", "endpoint", "usb", "connect"]
  },
  {
    "id": 25,
    "title": "Browser Extension Installation",
    "platform": "defender",
    "subcategory": "Defender for Endpoint",
    "date": "2026-07-10",
    "description": "Returns with installed browser extensions.",
    "query": `let device_name = "DEVICENAME";
let UnsanctionedExtensions = externaldata (ExtensionID: string) [@'https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Intune/Intune%20Browser%20Extension_IDs_the_user_should_be_prevented_from_installing.csv'] with (format=txt);
let RiskyExtensionsWithNames = externaldata (ExtensionID: string,ExtensionURL:string, ExtensionName:string) [@'https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Intune/Unsanctioned_extensions_with_names.csv'] with (format=csv, ignoreFirstRecord = true);
DeviceFileEvents
| where TimeGenerated > ago(5d)
| where ActionType == "FileCreated"
| where FileName endswith ".crx"
| where DeviceName contains device_name
| where FolderPath contains "Webstore Downloads"
| extend ExtensionID = trim_end(@"_\d{2,6}.crx", FileName)
| extend ExtensionURL = strcat("https://chrome.google.com/webstore/detail/",ExtensionID)
| extend EdgeExtensionURL = strcat("https://microsoftedge.microsoft.com/addons/detail/",ExtensionID)
| extend RiskyExtension = iff((ExtensionID in~(UnsanctionedExtensions)), "Yes","N/A")
| join kind=leftouter RiskyExtensionsWithNames on ExtensionID
| project Timestamp, Action = "Extension installed", DeviceName, ExtensionID, ExtensionURL, EdgeExtensionURL, RiskyExtension`,
    "tags": ["defender", "endpoint", "browser", "extension"]
  },
  {
    "id": 26,
    "title": "User Login Events",
    "platform": "crowdstrike",
    "subcategory": "CrowdStrike",
    "date": "2026-07-13",
    "description": "Retrieves user login events.",
    "query": `| in(field="#event_simpleName", values=["SsoApplicationAccess", "SsoApplicationAccessFailure", "SsoUserLogon"])
| source.ip=?Source_IP
| user.name=?Username
| LocationCountryCode=?Location_code
| table([@timestamp, #event_simpleName, #event.outcome, ClientUserAgentString, ClientIdentifier, source.address, LocationCountryCode, LocationAsnOrganization, SourceEndpointHostName, user.name])
// | timeChart(span=1d, series=LocationCountryCode) // If time chart needed
// | groupBy([LocationCountryCode]) // or render piechart with the "Auto (Event List) button.`,
    "tags": ["crowdstrike", "user", "login"]
  },
  {
    "id": 27,
    "title": "List of attachments sent from Outlook",
    "platform": "crowdstrike",
    "subcategory": "CrowdStrike",
    "date": "2026-07-13",
    "description": "Retrieves list of attachments sent from Outlook application.",
    "query": `#event_simpleName=ProcessRollup2
| CommandLine=/content.outlook/i
| ComputerName=?ComputerName
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| FileName=/(winword|excel|powerpnt)\.exe/i
| CommandLine=/Outlook\\(?<ShortFile>\w*\\.*)$/i
| table([@timestamp, aid, TargetProcessId, ShortFile, CommandLine], limit=1000)`,
    "tags": ["crowdstrike", "user", "login"]
  },
  {
    "id": 28,
    "title": "Remote Monitoring and Management (RMM) Tool Execution - Anydesk",
    "platform": "darktrace",
    "subcategory": "DarkTrace",
    "date": "2026-07-31",
    "description": "Retrieves Anydesk tool usage related network connections.",
    "query": `(@fields.dest_port:(80 443 6568) @fields.src_ip:"SOURCEIP") OR (@fields.src_ip:"SOURCEIP" /*.net.anydesk.*/)`,
    "tags": ["darktrace", "rmm", "anydesk"]
  },
  {
    "id": 29,
    "title": "Remote Monitoring and Management (RMM) Tool Execution - TeamViewer",
    "platform": "darktrace",
    "subcategory": "DarkTrace",
    "date": "2026-07-31",
    "description": "Retrieves TeamViewer tool usage related network connections.",
    "query": `(@fields.src_ip:"SOURCEIP" AND @fields.dest_port:"5938" AND @fields.local_resp:"false") OR (@fields.src_ip:"SOURCEIP" AND (@fields.host: /.*teamviewer.*/ OR @fields.server_name: /.*teamviewer.*/ OR @fields.query: /.*teamviewer.*/ )) OR /.*[Dd]yngate.*/`,
    "tags": ["darktrace", "rmm", "anydesk"]
  },
  {
    "id": 30,
    "title": "Remote Monitoring and Management (RMM) Tool Execution - VNC",
    "platform": "darktrace",
    "subcategory": "DarkTrace",
    "date": "2026-07-31",
    "description": "Retrieves VNC tool usage related network connections.",
    "query": `(@fields.src_port:(5901 OR 5902 OR 5903 OR 5904 OR 5905 OR 5906 OR 5907 OR 5908 OR 5909 OR 5910) AND @fields.src_ip:"SOURCEIP") OR (@fields.src_ip:"SOURCEIP" AND @fields.src_port:(5900 OR 5901 OR 5902 OR 5903 OR 5904 OR 5905 5906 OR 5907 OR 5908 OR 5909 OR 5910))`,
    "tags": ["darktrace", "rmm", "anydesk"]
  },
  {
    "id": 31,
    "title": "Service registration and scheduled task creation",
    "platform": "defender",
    "subcategory": "Microsoft Defender for Endpoint",
    "date": "2026-07-31",
    "description": "Retrieves registered services and created schedules tasks.",
    "query": `let startTime = todatetime("2026-04-30 15:30"); // 2 hours difference 
let endTime = todatetime("2026-04-30 16:00"); // 2 hours difference 
let device_name = "DEVICENAME";
DeviceEvents
| where Timestamp between (startTime .. endTime) and DeviceName contains device_name and FileName !in ("svchost.exe")
| where ActionType in ("ServiceInstalled", "ServiceStarted", "ScheduledTaskCreated", "ScheduledTaskStarted")
| extend ParsedFields = parse_json(AdditionalFields)
| extend ObjectName = case(
    ActionType startswith "Service", tostring(ParsedFields.ServiceName),
    ActionType startswith "ScheduledTask", tostring(ParsedFields.TaskName),
    "N/A"
)
| extend ObjectDetail = case(
    ActionType startswith "Service", tostring(ParsedFields.ServiceType),
    "N/A"
)
| project Timestamp, ActionType, FileName, FolderPath, ObjectName, ObjectDetail
| sort by Timestamp asc`,
    "tags": ["defender", "task", "service", "registration"]
  },
  {
    "id": 32,
    "title": "Informations about an URL in Microsoft Teams chat",
    "platform": "defender",
    "subcategory": "Microsoft Defender for Office 365",
    "date": "2026-07-31",
    "description": "Retrieves URLs from a specified Microsoft Team chat.",
    "query": `MessageUrlInfo
| where TeamsMessageId contains "TEAMS_CHAT_ID"
| sort by Timestamp asc`,
    "tags": ["defender", "teams", "url"]
  },
  {
    "id": 33,
    "title": "User call activities",
    "platform": "defender",
    "subcategory": "Microsoft Defender for Office 365",
    "date": "2026-07-31",
    "description": "Retrieves the user Microsoft Teams call events.",
    "query": `CallActivityEvents
| where ActivityInitiatorUpn == "EMAIL@domain.com"
| sort by ActivityTimestamp desc`,
    "tags": ["defender", "teams", "url"]
  },
  {
    "id": 34,
    "title": "Email trend chart",
    "platform": "defender",
    "subcategory": "Microsoft Defender for Office 365",
    "date": "2026-07-31",
    "description": "Retrieves a chart by the email trend.",
    "query": `let Recipient = "EMAIL@domain.com";
EmailEvents
| where Timestamp > ago(1d)
| where RecipientEmailAddress contains Recipient
| summarize EventCount = count() by bin(Timestamp, 1h)
| render timechart`,
    "tags": ["defender", "email", "chart"]
  },
	{
    "id": 35,
    "title": "Successful signin from new country",
    "platform": "defender",
    "subcategory": "Microsoft Defender for Identity",
    "date": "2026-08-27",
    "description": "This query detects successful signins from countries that have not been seen before",
    "query": `let Lookback = 3d;
let UPN = "UPN";
let KnownCountries = EntraIdSignInEvents
    | where Timestamp > ago(30d) and Timestamp < ago(Lookback)
    | where AccountUpn contains UPN
    | where ErrorCode == 0
    | where isnotempty(Country)
    | distinct Country;
EntraIdSignInEvents
| where Timestamp > ago(Lookback)
| where AccountUpn contains UPN
| where ErrorCode == 0
| where isnotempty(Country)
| where Country !in (KnownCountries)
| project Timestamp, Country, UserAgent, ErrorCode, AccountObjectId,AccountDisplayName, IPAddress`,
    "tags": ["defender", "identity", "entra id", "sign-in"]
  },
	{
    "id": 36,
    "title": "Successful device code sign-in from unmanaged device",
    "platform": "defender",
    "subcategory": "Microsoft Defender for Identity",
    "date": "2026-08-27",
    "description": "This query lists successful Entra ID sign-ins were device code authentication is used from an unmanaged device.",
    "query": `AADSignInEventsBeta
// Filter only successful sign-ins
| where ErrorCode == 0
| where EndpointCall == "Cmsi:Cmsi"
// Filter on unmanaged devices
| where isempty(AadDeviceId)
// Optionally filter only on sign-ins with a risklevel associated with the sign-in
//| where RiskLevelDuringSignIn in(10, 50, 100)
| project-reorder TimeGenerated, AccountUpn, EndpointCall, ErrorCode, RiskLevelDuringSignIn, Application, ApplicationId, Country, IPAddress`,
    "tags": ["defender", "identity", "entra id", "sign-in"]
  }
];
