using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace WebAuthTest.Controllers
{
    public class HomeController : Controller
    {
        private IFido2 _fido2 { get; }
        public static readonly DevelopmentInMemoryStore DemoStorage = new DevelopmentInMemoryStore();

        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public JsonResult RegisterCredentialStart(string username, string displayName,
            string attType, string authType, bool requireResidentKey, string userVerification)
        {
            if (string.IsNullOrEmpty(username))
            {
                username = $"{displayName} (Usernameless user created at {DateTime.UtcNow})";
            }

            // 1. Get user from DB by username (in our example, auto create missing users)
            Fido2User user = DemoStorage.GetOrAddUser(username, () => new Fido2User
            {
                DisplayName = displayName,
                Name = username,
                Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
            });

            // 2. Get user existing keys by username
            List<PublicKeyCredentialDescriptor> existingKeys = DemoStorage
                .GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

            // 3. Create options
            AuthenticatorSelection authenticatorSelection = new AuthenticatorSelection
            {
                RequireResidentKey = requireResidentKey,
                UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
            };

            if (!string.IsNullOrEmpty(authType))
                authenticatorSelection.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();

            AuthenticationExtensionsClientInputs exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationIndex = true,
                Location = true,
                UserVerificationMethod = true,
                BiometricAuthenticatorPerformanceBounds = new AuthenticatorBiometricPerfBounds
                {
                    FAR = float.MaxValue,
                    FRR = float.MaxValue
                }
            };

            CredentialCreateOptions options = _fido2.RequestNewCredential(user, existingKeys, authenticatorSelection,
                attType.ToEnum<AttestationConveyancePreference>(), exts);

            // 4. Temporarily store options, session/in-memory cache/redis/db
            Session["fido2.attestationOptions"] = options.ToJson();

            // 5. return options to client
            return Json(options);
        }

        [HttpPost]
        public JsonResult RegisterCredentialFinish(string json)
        {
            CredentialCreateOptions.FromJson(json);
            return Json(new { }, JsonRequestBehavior.DenyGet);
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}