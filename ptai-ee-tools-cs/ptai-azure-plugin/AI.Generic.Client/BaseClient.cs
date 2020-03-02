using AI.Enterprise.Integration.RestApi.Api;
using AI.Enterprise.Integration.RestApi.Client;
using AI.Enterprise.Integration.RestApi.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace AI.Generic.Client {
    public class BaseClient {
        protected readonly static string clientId = "ptai-azure-plugin";
        protected readonly static string clientSecret = "wdjJd0DeWtW4SLB4K01Xy8ljQ5KKJH1Q";

        protected string username = null;
        protected string password = null;

        protected JwtResponse jwt = null;
        protected IOauthControllerApi oauth = null;

        public BaseClient(string basePath) {
            this.oauth = new OauthControllerApi(basePath);
            this.oauth.Configuration.Username = clientId;
            this.oauth.Configuration.Password = clientSecret;
        }

        public BaseClient init(string username, string password, string ca) {
            this.username = username;
            this.password = password;
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            return this;
        }

        protected JwtResponse GetToken() {
            return this.oauth.GetJwtTokenUsingPOST(this.username, this.password, null, "password");
        }
        protected JwtResponse RefreshToken() {
            return this.oauth.GetJwtTokenUsingPOST(null, null, this.jwt.RefreshToken, "refresh_token");
        }

        public JwtResponse Login() {
            if (null == this.jwt)
                this.jwt = this.GetToken();
            else {
                try {
                    this.jwt = this.RefreshToken();
                } catch (ApiException e) {
                    this.jwt = this.GetToken();
                }
            }
            return this.jwt;
        }
    }
}
