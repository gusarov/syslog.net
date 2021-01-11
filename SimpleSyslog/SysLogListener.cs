using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SimpleSyslog
{
	public class SysLogListener
	{
		readonly UdpClient _udp;

		public SysLogListener()
		{
			_udp = new UdpClient(514);
			ReceiveWorker();
		}

		public event EventHandler<LogEventArgs> LogMessage;

		void OnLogMessage(SyslogMessage msg)
		{
			LogMessage?.Invoke(this, new LogEventArgs(msg));
		}

		async Task ReceiveWorker()
		{
			var diag = await _udp.ReceiveAsync();
			//var str = Encoding.UTF8.GetString(diag.Buffer);
			// Console.WriteLine($"{str}");
			try
			{
				var msg = SyslogMessage.Deserialzie(diag.Buffer);
				OnLogMessage(msg);
			}
			catch
			{
				// otherwise the sequence would be broken
			}
			//Console.WriteLine($"From {diag.RemoteEndPoint.Address} received {diag.Buffer.Length} bytes.");
			await ReceiveWorker();
		}
	}

	public class LogEventArgs : EventArgs
	{
		public LogEventArgs(SyslogMessage msg)
		{
			Msg = msg;
		}

		public SyslogMessage Msg { get; }
	}

	public enum Facility
	{
		KernelMessages = 0,
		UserLevelMessages = 1,
		MailSystem = 2,
		SystemDaemons = 3,
		SecurityOrAuthorizationMessages1 = 4,
		InternalMessages = 5,
		LinePrinterSubsystem = 6,
		NetworkNewsSubsystem = 7,
		UUCPSubsystem = 8,
		ClockDaemon1 = 9,
		SecurityOrAuthorizationMessages2 = 10,
		FTPDaemon = 11,
		NTPSubsystem = 12,
		LogAudit = 13,
		LogAlert = 14,
		ClockDaemon2 = 15,
		LocalUse0 = 16,
		LocalUse1 = 17,
		LocalUse2 = 18,
		LocalUse3 = 19,
		LocalUse4 = 20,
		LocalUse5 = 21,
		LocalUse6 = 22,
		LocalUse7 = 23
	}

	public enum Severity
	{
		/// <summary>
		/// System is unusable
		/// </summary>
		Emergency = 0,
		/// <summary>
		/// Action must be taken immediately
		/// </summary>
		Alert = 1,
		/// <summary>
		/// Critical conditions
		/// </summary>
		Critical = 2,
		/// <summary>
		/// Error conditions
		/// </summary>
		Error = 3,
		/// <summary>
		/// Warning conditions
		/// </summary>
		Warning = 4,
		/// <summary>
		/// Normal but significant condition
		/// </summary>
		Notice = 5,
		/// <summary>
		/// Informational messages
		/// </summary>
		Informational = 6,
		/// <summary>
		/// Debug-level messages
		/// </summary>
		Debug = 7
	}

	public class SyslogMessage
	{
		public override string ToString()
		{
			return $@"{Facility} {Severity} {Time:yyyy-MM-dd HH:mm:ss} {AppName}: {Message}";
		}

		public static SyslogMessage Deserialzie(byte[] buf)
		{
			try
			{
				var b = Encoding.UTF8.GetString(buf);
				var parsed = Regex.Match(b, @"<(?'p'\d+)>\s*(?'t'\w\w\w \d+ \d\d:\d\d:\d\d)\s*(?'s'\w+)\s*:\s*(?'r'.*)");
				var priority = int.Parse(parsed.Groups["p"].Value);

				var severity = (Severity)(priority & 7);
				var facility = (Facility)(priority >> 3);

				var time = DateTime.ParseExact(DateTime.UtcNow.Year + " " + parsed.Groups["t"].Value, "yyyy MMM dd HH:mm:ss", CultureInfo.InvariantCulture);

				var source = parsed.Groups["s"].Value;
				var message = parsed.Groups["r"].Value;

				// Console.WriteLine($@"{facility} {severity} {time} {source}: {message}");

				return new SyslogMessage(time, facility, severity, null, source, message);
			}
			catch (Exception ex)
			{
				return new SyslogMessage(Severity.Critical, "SysLogDaemon", "Parse Exception: " + ex.ToString());
			}
			/*
			var priorityValue = CalculatePriorityValue(message.Facility, message.Severity);

			
			string timestamp = null;
			if (message.DateTimeOffset.HasValue)
			{
				var dt = message.DateTimeOffset.Value;
				var day = dt.Day < 10 ? " " + dt.Day : dt.Day.ToString(); // Yes, this is stupid but it's in the spec
				timestamp = String.Concat(dt.ToString("MMM "), day, dt.ToString(" HH:mm:ss"));
			}

			var headerBuilder = new StringBuilder();
			headerBuilder.Append("<").Append(priorityValue).Append(">");

			headerBuilder.Append(timestamp).Append(" ");

			headerBuilder.Append(message.HostName).Append(" ");
			headerBuilder.Append(message.AppName.IfNotNullOrWhitespace(x => x.EnsureMaxLength(32) + ":"));
			headerBuilder.Append(message.Message ?? "");

			byte[] asciiBytes = Encoding.ASCII.GetBytes(headerBuilder.ToString());
			stream.Write(asciiBytes, 0, asciiBytes.Length);
			*/
		}

		public static Facility DefaultFacility = Facility.UserLevelMessages;
		public static Severity DefaultSeverity = Severity.Informational;

		/// <summary>
		/// Convenience overload for sending local syslog messages with default facility (UserLevelMessages)
		/// </summary>
		public SyslogMessage(
			Severity severity,
			string appName,
			string message)
		: this(DefaultFacility, severity, appName, message)
		{
		}

		/// <summary>
		/// Constructor for use when sending local syslog messages
		/// </summary>
		public SyslogMessage(
			Facility facility,
			Severity severity,
			string appName,
			string message)
		{
			Facility = facility;
			Severity = severity;
			AppName = appName;
			Message = message;
		}

		/// <summary>
		/// Constructor for use when sending RFC 3164 messages
		/// </summary>
		public SyslogMessage(
			DateTime time,
			Facility facility,
			Severity severity,
			string hostName,
			string appName,
			string message)
		{
			Time = time;
			Facility = facility;
			Severity = severity;
			HostName = hostName;
			AppName = appName;
			Message = message;
		}

		/// <summary>
		/// Constructor for use when sending RFC 5424 messages
		/// </summary>
		public SyslogMessage(
			DateTime time,
			Facility facility,
			Severity severity,
			string hostName,
			string appName,
			string procId,
			string msgId,
			string message,
			params StructuredDataElement[] structuredDataElements)
			: this(time, facility, severity, hostName, appName, message)
		{
			ProcId = procId;
			MsgId = msgId;
			StructuredDataElements = structuredDataElements;
		}

		public int Version
		{
			get { return 1; }
		}

		public Facility Facility { get; set; }

		public Severity Severity { get; set; }

		// public DateTimeOffset? DateTimeOffset { get; set; }
		public DateTime Time { get; set; }

		public string HostName { get; set; }

		public string AppName { get; set; }

		public string ProcId { get; set; }

		public string MsgId { get; set; }

		public string Message { get; set; }

		public IEnumerable<StructuredDataElement> StructuredDataElements { get; set; }
	}

	public class StructuredDataElement
	{
		// RFC 5424 specifies that you must provide a private enterprise number. If none specified, using example number reserved for documentation (see RFC)
		public const string DefaultPrivateEnterpriseNumber = "32473";

		private readonly string sdId;
		private readonly Dictionary<string, string> parameters;

		public StructuredDataElement(string sdId, Dictionary<string, string> parameters)
		{
			this.sdId = sdId.Contains("@") ? sdId : sdId + "@" + DefaultPrivateEnterpriseNumber;
			this.parameters = parameters;
		}

		public string SdId
		{
			get { return sdId; }
		}

		public Dictionary<string, string> Parameters
		{
			get { return parameters; }
		}
	}
}