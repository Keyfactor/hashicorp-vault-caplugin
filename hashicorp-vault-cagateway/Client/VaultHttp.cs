// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.Client
{
    // this class handles the communication protocols and headers from our plugin to Vault
    public class VaultHttp
    {

        private static readonly ILogger logger = LogHandler.GetClassLogger<VaultHttp>();

        //private string _vaultHostUrl { get; set; }
        //private string _namespace { get; set; }
        private string _mountPoint { get; set; }
        //private string _authToken { get; set; }
        private RestClient _restClient { get; set; }

        public VaultHttp(string host, string mountPoint, string authToken, string nameSpace = null)
        {

            var restClientOptions = new RestClientOptions($"{host.TrimEnd('/')}/v1");
            //{
            //    Interceptors = [ new CompatibilityInterceptor {
            //    OnBeforeDeserialization = _ => { _.ContentType = "application/json"; } // vault doesn't send this header, but always sends JSON
            //}]};
            _mountPoint = mountPoint.TrimStart('/').TrimEnd('/'); // remove leading and trailing slashes
            logger.LogTrace($"mount point: {_mountPoint}");
            _restClient = new RestClient(restClientOptions);
            //_restClient.AddDefaultHeader(KnownHeaders.ContentType, "application/json");
            _restClient.AddDefaultHeader("X-Vault-Request", "true");
            _restClient.AddDefaultHeader("X-Vault-Token", authToken);
            if (nameSpace != null) _restClient.AddDefaultHeader("X-Vault-Namespace", nameSpace);

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
            logger.LogTrace($"preparing to send GET request to {path} with parameters {JsonSerializer.Serialize(parameters)}");
            logger.LogTrace($"will attempt to deserialize the response into a {typeof(T)}");
            try
            {
                var request = new RestRequest($"{_mountPoint}/{path}", Method.Get).AddJsonBody(parameters);
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

        public async Task<T> PostAsync<T>(string path, dynamic parameters = default)
        {
            logger.MethodEntry();
            var resourcePath = $"{_mountPoint}/{path}";
            logger.LogTrace($"preparing to send POST request to {_restClient.Options.BaseUrl}{resourcePath}");
            logger.LogTrace($"will attempt to deserialize the response into a {typeof(T)}");
            JsonSerializerOptions options = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
            string serializedParams = JsonSerializer.Serialize(parameters, options);
            logger.LogTrace($"serialized parameters (from {parameters.GetType()?.Name}): {serializedParams}");

            try
            {
                var request = new RestRequest(resourcePath, Method.Post).AddStringBody(serializedParams, DataFormat.Json);

                logger.LogTrace($"full url for the request: {_restClient.Options.BaseUrl}/{request.Resource}");

                logger.LogTrace($"Added the parameters to the request: {JsonSerializer.Serialize(request.Parameters)}");

                var response = await _restClient.ExecutePostAsync(request);
                string content = response.Content.ToString();
                logger.LogTrace($"request completed. response content returned: {content}");
                //response.ThrowIfError();
                logger.LogTrace($"response.StatusCode: {response.StatusCode}");
                logger.LogTrace($"response.contentType: {response.ContentType}");
                logger.LogTrace($"response.Content: {content}");
                logger.LogTrace($"response.ErrorMessage: {response.ErrorMessage}");
                T result;

                ErrorResponse errorResponse = null;
                if (response.StatusCode == System.Net.HttpStatusCode.BadRequest)
                {
                    errorResponse = JsonSerializer.Deserialize<ErrorResponse>(response.Content);
                    var allErrors = string.Join(",", errorResponse.Errors);
                    logger.LogTrace($"errors: {allErrors}");
                    throw new Exception(allErrors);
                }

                result = JsonSerializer.Deserialize<T>(response.Content);
                return result;
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
                return await _restClient.GetAsync<SealStatusResponse>("sys/seal-status");
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
                var response = await _restClient.GetAsync<dynamic>("sys/capabilities/self");
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

        public string Configuration { get { return _restClient.Options.ToString(); } }
    }
}
