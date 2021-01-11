using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MongoDB.Driver;
using SimpleSyslog;

namespace SimpleSysLog.ConsoleApp
{
	class Program
	{
		static IMongoDatabase db;

		static void Main(string[] args)
		{
			var con = new MongoClient("mongodb://localhost");
			db = con.GetDatabase("SysLog");
			var srv = new SysLogListener();
			srv.LogMessage += Srv_LogMessage;
			System.Console.ReadLine();
		}

		private static void Srv_LogMessage(object sender, LogEventArgs e)
		{
			System.Console.WriteLine(e.Msg);
			db.GetCollection<SyslogMessage>("SysLog").InsertOne(e.Msg);
		}
	}

}
