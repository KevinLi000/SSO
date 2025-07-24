	public class AzureAdTokenValidator
	{
		private readonly string _authority;
		private readonly string _issuer;
		private readonly string _audience;
		private readonly ConfigurationManager<OpenIdConnectConfiguration> _configuration;
		private readonly bool _validateLifetime;
		private readonly List<SecurityKey> _additionalSigningKeys;

		public AzureAdTokenValidator(string tenantId, string clientId, bool validateLifetime = true)
		{
			_authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
			_issuer = $"https://sts.windows.net/{tenantId}/"; // This is the issuer for tokens from Azure AD
			_audience = clientId;
			_validateLifetime = validateLifetime;
			_additionalSigningKeys = new List<SecurityKey>();

			// Set up TLS 1.2
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
			IdentityModelEventSource.ShowPII = true;
			var documentRetriever = new HttpDocumentRetriever();
			// Set documentRetriever to require HTTPS
			documentRetriever.RequireHttps = true;
			
			_configuration = new ConfigurationManager<OpenIdConnectConfiguration>(
				$"{_authority}/.well-known/openid-configuration", 
				new OpenIdConnectConfigurationRetriever(),
				documentRetriever
			);
		}

		/// <summary>
		/// Adds an additional signing key to use for token validation
		/// </summary>
		/// <param name="certificate">The X509 certificate containing the public key</param>
		public void AddSigningKey(X509Certificate2 certificate)
		{
			if (certificate == null)
				throw new ArgumentNullException(nameof(certificate));

			var securityKey = new X509SecurityKey(certificate);
			_additionalSigningKeys.Add(securityKey);
			Console.WriteLine($"Added additional signing key with ID: {securityKey.KeyId}");
		}

		/// <summary>
		/// Validates the JWT token
		/// </summary>
		/// <param name="accessToken">The access token</param>
		public async Task<ClaimsPrincipal> ValidateTokenAsync(string accessToken)
		{
			try
			{
				// Force refresh configuration before validation to ensure we have the latest keys
				var config = await _configuration.GetConfigurationAsync();
                
				Console.WriteLine($"Found {config.SigningKeys.Count} signing keys from issuer.");
				foreach (var key in config.SigningKeys)
				{
					Console.WriteLine($"Key type: {key.GetType().Name}, Key ID: {key.KeyId}");
				}

				// Check if there are any additional signing keys
				if (_additionalSigningKeys.Count > 0)
				{
					Console.WriteLine($"Using {_additionalSigningKeys.Count} additional signing keys.");
				}

				var handler = new JwtSecurityTokenHandler();
				
				// Check if token is readable and well-formed
				if (!handler.CanReadToken(accessToken))
				{
					throw new Exception("The token is not well-formed or cannot be read.");
				}

				// Read token without validation to inspect its claims
				var jwtToken = handler.ReadJwtToken(accessToken);
				Console.WriteLine($"Token kid: {jwtToken.Header.Kid}");
				Console.WriteLine($"Token alg: {jwtToken.Header.Alg}");
				Console.WriteLine($"Token issuer: {jwtToken.Issuer}");
				Console.WriteLine($"Token audience: {string.Join(", ", jwtToken.Audiences)}");
				Console.WriteLine($"Token valid from: {jwtToken.ValidFrom.ToLocalTime()}");
				Console.WriteLine($"Token valid to: {jwtToken.ValidTo.ToLocalTime()}");

				// Combine issuer's signing keys with our additional keys
				var allSigningKeys = new List<SecurityKey>(config.SigningKeys);
				allSigningKeys.AddRange(_additionalSigningKeys);

				var tokenValidationParameters = new TokenValidationParameters
				{
					ValidateIssuer = false,
					ValidIssuer = _authority,
					ValidateAudience = true,
					ValidAudience = _audience,
					ValidateLifetime = _validateLifetime,
					RequireSignedTokens = true,
					IssuerSigningKeys = allSigningKeys,
					ValidateIssuerSigningKey = true,
					// Set ClockSkew to accommodate for time differences between server and token issuer
					ClockSkew = TimeSpan.FromMinutes(5)
				};

				// Perform the actual token validation
				SecurityToken validatedToken;
				var principal = handler.ValidateToken(accessToken, tokenValidationParameters, out validatedToken);

				Console.WriteLine("Token validation successful!");
				return principal;
			}
			catch (SecurityTokenExpiredException ex)
			{
				Console.WriteLine($"Token expired: {ex.Message}. Try setting validateLifetime = false if testing with expired tokens.");
				throw;
			}
			catch (SecurityTokenInvalidSignatureException ex)
			{
				Console.WriteLine($"Invalid signature: {ex.Message}");
				Console.WriteLine("This means the token couldn't be verified with any of the available signing keys.");
				Console.WriteLine("Check if the token was signed with a key not available in the OpenID configuration.");
				
				// Analyze token header to get more info
				var handler = new JwtSecurityTokenHandler();
				if (handler.CanReadToken(accessToken))
				{
					var token = handler.ReadJwtToken(accessToken);
					Console.WriteLine($"Token kid (Key ID): {token.Header.Kid}");
					Console.WriteLine($"Token alg (Algorithm): {token.Header.Alg}");
					Console.WriteLine($"This key ID is missing from the issuer's signing keys.");
				}
				
				throw;
			}
			catch (Exception ex)
			{
				Console.WriteLine($"Token validation failed: {ex.GetType().Name} - {ex.Message}");
				if (ex.InnerException != null)
				{
					Console.WriteLine($"Inner exception: {ex.InnerException.GetType().Name} - {ex.InnerException.Message}");
				}
				Console.WriteLine($"Stack trace: {ex.StackTrace}");
				throw;
			}
		}
	}