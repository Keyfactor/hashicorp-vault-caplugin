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
using RestSharp.Serializers.Json;
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.Client
{
    /// <summary>
    /// This class encapsulates a restsharp client configured for communication to the Vault API
    /// </summary>
    public class VaultHttp
    {
        private string _mountPoint { get; set; }  // not all requests are the the secrets engine, so can't append this permanently to the base path
        private RestClient _restClient { get; set; }
        private JsonSerializerOptions _serializerOptions { get; set; }

        private static readonly ILogger logger = LogHandler.GetClassLogger<VaultHttp>();

        public VaultHttp(string host, string mountPoint, string authToken, string nameSpace = null)
        {
            logger.MethodEntry();

            _serializerOptions = new()
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
                RespectNullableAnnotations = true,
                PropertyNameCaseInsensitive = true,
                PreferredObjectCreationHandling = JsonObjectCreationHandling.Replace,
            };

            var restClientOptions = new RestClientOptions($"{host.TrimEnd('/')}/v1") { ThrowOnAnyError = true };
            _restClient = new RestClient(restClientOptions, configureSerialization: s => s.UseSystemTextJson(_serializerOptions));

            _mountPoint = mountPoint.TrimStart('/').TrimEnd('/'); // remove leading and trailing slashes
            _restClient.AddDefaultHeader("X-Vault-Request", "true");
            _restClient.AddDefaultHeader("X-Vault-Token", authToken);

            if (nameSpace != null) _restClient.AddDefaultHeader("X-Vault-Namespace", nameSpace);

            logger.LogTrace($"configured an instance of our restsharp client with the provided values:");
            logger.LogTrace($"host url: {host}");
            logger.LogTrace($"mount point: {_mountPoint}");
            logger.LogTrace($"namespace: {nameSpace}");

            logger.MethodExit();
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
                var request = new RestRequest($"{_mountPoint}/{path}", Method.Get);
                if (parameters != null) { request.AddJsonBody(parameters); }

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

            try
            {
                var request = new RestRequest(resourcePath, Method.Post);
                if (parameters != null)
                {
                    string serializedParams = JsonSerializer.Serialize(parameters, _serializerOptions);
                    logger.LogTrace($"serialized parameters (from {parameters.GetType()?.Name}): {serializedParams}");
                    request.AddJsonBody(serializedParams);
                }

                logger.LogTrace($"full url for the request: {_restClient.Options.BaseUrl}/{request.Resource}");

                var response = await _restClient.ExecutePostAsync<T>(request);

                logger.LogTrace($"request completed. response returned:");
                logger.LogTrace($"response.StatusCode: {response!.StatusCode}");
                logger.LogTrace($"response.contentType: {response!.ContentType}");
                
                if (response.ErrorMessage != null) logger.LogTrace($"response.ErrorMessage: {response!.ErrorMessage}");

                ErrorResponse errorResponse = null;

                if (response.StatusCode == System.Net.HttpStatusCode.BadRequest)
                {
                    errorResponse = JsonSerializer.Deserialize<ErrorResponse>(response.Content!);
                    string allErrors = "(Bad Request)";
                    if (errorResponse?.Errors.Count > 0)
                    {
                        allErrors = string.Join(",", errorResponse.Errors);
                    }
                    logger.LogTrace($"errors: {allErrors}");
                    throw new Exception(allErrors);
                }
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
                return await _restClient.GetAsync<SealStatusResponse>("sys/seal-status");
            }
            catch (Exception ex)
            {
                logger.LogError($"there was an error making the request: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally { logger.MethodExit(); }
        }

        /// <summary>
        /// gets the capabilities for the current token in the given namespace.
        /// using this method to verify connectivity
        /// </summary>
        /// <returns></returns>
        public async Task<List<string>> GetCapabilitiesForThisTokenAndNamespace()
        {
            logger.MethodEntry();
            try
            {
                var response = await _restClient.GetAsync<dynamic>("sys/capabilities/self");
                response!.ThrowIfError();
                return response.Content?.data?.capabilities as List<string>;
            }
            catch (Exception ex)
            {
                logger.LogError($"request to get capabilities for token failed: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally { logger.MethodExit(); }
        }
    }
}
