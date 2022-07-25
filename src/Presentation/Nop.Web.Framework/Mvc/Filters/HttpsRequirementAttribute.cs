using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Nop.Core;
using Nop.Data;

namespace Nop.Web.Framework.Mvc.Filters
{
    /// <summary>
    /// Represents a filter attribute that checks whether current connection is secured and properly redirect if necessary
    /// </summary>
    public sealed class HttpsRequirementAttribute : TypeFilterAttribute
    {
        #region Ctor

        /// <summary>
        /// Create instance of the filter attribute
        /// </summary>
        public HttpsRequirementAttribute(bool ignore = false) : base(typeof(HttpsRequirementFilter))
        {
            IgnoreFilter = ignore;
            Arguments = new object[] { ignore };
        }

        #endregion

        #region Properties

        /// <summary>
        /// Gets a value indicating whether to ignore the execution of filter actions
        /// </summary>
        public bool IgnoreFilter { get; }

        #endregion

        #region Nested filter

        /// <summary>
        /// Represents a filter confirming that checks whether current connection is secured and properly redirect if necessary
        /// </summary>
        private class HttpsRequirementFilter : IAsyncAuthorizationFilter
        {
            #region Fields

            private readonly bool _ignoreFilter;
            private readonly IStoreContext _storeContext;
            private readonly IWebHelper _webHelper;

            #endregion

            #region Ctor

            public HttpsRequirementFilter(bool ignoreFilter, IStoreContext storeContext, IWebHelper webHelper)
            {
                _ignoreFilter = ignoreFilter;
                _storeContext = storeContext;
                _webHelper = webHelper;
            }

            #endregion

            #region Utilities

            /// <summary>
            /// Called early in the filter pipeline to confirm request is authorized
            /// </summary>
            /// <param name="context">Authorization filter context</param>
            /// <returns>A task that represents the asynchronous operation</returns>
            private async Task CheckHttpsRequirementAsync(AuthorizationFilterContext context)
            {
                if (context == null)
                    throw new ArgumentNullException(nameof(context));

                if (context.HttpContext.Request == null)
                    return;

                //only in GET requests, otherwise the browser might not propagate the verb and request body correctly
                if (!context.HttpContext.Request.Method.Equals(WebRequestMethods.Http.Get, StringComparison.InvariantCultureIgnoreCase))
                    return;

                if (!DataSettingsManager.IsDatabaseInstalled())
                    return;

                //check whether this filter has been overridden for the action
                var actionFilter = context.ActionDescriptor.FilterDescriptors
                    .Where(filterDescriptor => filterDescriptor.Scope == FilterScope.Action)
                    .Select(filterDescriptor => filterDescriptor.Filter)
                    .OfType<HttpsRequirementAttribute>()
                    .FirstOrDefault();

                //ignore filter (the action is available even if a customer hasn't access to the admin area)
                if (actionFilter?.IgnoreFilter ?? _ignoreFilter)
                    return;

                var store = await _storeContext.GetCurrentStoreAsync();

                //whether current connection is secured
                var currentConnectionSecured = _webHelper.IsCurrentConnectionSecured();

                //page should be secured, so redirect (permanent) to HTTPS version of page
                if (store.SslEnabled && !currentConnectionSecured)
                    context.Result = new RedirectResult(_webHelper.GetThisPageUrl(true, true), true);

                //page shouldn't be secured, so redirect (permanent) to HTTP version of page
                if (!store.SslEnabled && currentConnectionSecured)
                    context.Result = new RedirectResult(_webHelper.GetThisPageUrl(true, false), true);
            }

            #endregion

            #region Methods

            /// <summary>
            /// Called early in the filter pipeline to confirm request is authorized
            /// </summary>
            /// <param name="context">Authorization filter context</param>
            /// <returns>A task that represents the asynchronous operation</returns>
            public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
            {
                await CheckHttpsRequirementAsync(context);
            }

            #endregion
        }

        #endregion
    }
}