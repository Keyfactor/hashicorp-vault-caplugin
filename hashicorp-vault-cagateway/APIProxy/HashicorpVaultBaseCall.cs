using Newtonsoft.Json;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault
{
    public abstract class ProductNameBaseRequest
	{
		[JsonIgnore]
		public string Resource { get; internal set; }

		[JsonIgnore]
		public string Method { get; internal set; }

		[JsonIgnore]
		public string targetURI { get; set; }

		public string BuildParameters()
		{
			return "";
		}
	}
}