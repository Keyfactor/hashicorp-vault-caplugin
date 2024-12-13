// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.Smime;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.Client
{
    // this class handles the communication protocols and headers from our plugin to Vault
    public class VaultHttp
    {

        private static readonly ILogger logger = LogHandler.GetClassLogger<VaultHttp>();

        private string _vaultHostUrl { get; set; }
        private string _namespace { get; set; }
        private string _mountPoint { get; set; }
        private string _authToken { get; set; }
        private RestClient _restClient { get; set; }

        public VaultHttp(string host, string mountPoint, string authToken, string nameSpace = null)
        {
            //_vaultHostUrl = host;
            //_namespace = nameSpace;
            //_mountPoint = mountPoint;
            //_authToken = authToken;

            var restClientOptions = new RestClientOptions($"{host}/v1/");
            _restClient = new RestClient(restClientOptions);
            _restClient.AddDefaultHeader("X-Vault-Request", "true");
            _restClient.AddDefaultHeader("X-Vault-Token", authToken);
            if (nameSpace != null) _restClient.AddDefaultHeader("X-Vault-Namespace", nameSpace);
            _restClient.AcceptedContentTypes = ContentType.JsonAccept;
        }

        /// <summary>
        /// Makes a request to the configured endpoint and provided path using the GET HTTP verb.
        /// </summary>
        /// <param name="path">The path to the resource where we will send the GET request.</param>
        /// <param name="parameters">A dictionary of values to be passed along with the request as query parameters.</param>
        /// <returns></returns>
        /// 

        public async Task<T> GetAsync<T>(string path, Dictionary<string, string> parameters = null)
        {
            logger.MethodEntry();
            try
            {
                var request = new RestRequest($"{_mountPoint}/{path}", Method.Get).AddObject(parameters);
                var response = await _restClient.ExecuteGetAsync<T>(request);

                response.ThrowIfError();

                return response.Data;
            }
            catch (Exception ex)
            {
                logger.LogError($"there was an error making the request: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally
            {
                logger.MethodExit();
            }
        }

        public async Task<T> PostAsync<T>(string path, object parameters = null)
        {
            logger.MethodEntry();
            try
            {
                var request = new RestRequest($"{_mountPoint}/{path}", Method.Post).AddObject(parameters);
                var response = await _restClient.ExecuteGetAsync<T>(request);

                response.ThrowIfError();

                return response.Data;
            }
            catch (Exception ex)
            {
                logger.LogError($"there was an error making the request: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally
            {
                logger.MethodExit();
            }
        }

        public async Task<SealStatusResponse> HealthCheckAsync()
        {
            logger.MethodEntry();

            try
            {
                return await _restClient.GetAsync<SealStatusResponse>("/v1/sys/seal-status");
            }
            catch (Exception ex)
            {
                logger.LogError($"there was an error making the request: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally { logger.MethodExit(); }
        }

        public async Task<List<string>> GetCapabilitiesForThisTokenAndNamespace()
        {
            logger.MethodEntry();
            // gets the capabilities for the current token in the given namespace
            // using this method to verify connectivity
            try
            {
                var response = await _restClient.GetAsync<dynamic>("v1/sys/capabilities/self");
                response.ThrowIfError();
                return response.Content?.data?.capabilities as List<string>;
            }
            catch (Exception ex)
            {
                logger.LogError($"request to get capabilities for token failed: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally { logger.MethodExit(); }
        }

        public string Configuration { get { return JsonConvert.SerializeObject(_restClient.Options); } }
    }
}
