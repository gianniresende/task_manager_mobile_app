"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core_1 = require("@angular/core");
var router_1 = require("@angular/router");
var http_1 = require("@angular/http");
var rxjs_1 = require("rxjs");
var operators_1 = require("rxjs/operators");
var application_settings_1 = require("application-settings");
var NSAngular2TokenService = /** @class */ (function () {
    function NSAngular2TokenService(http, activatedRoute, router) {
        this.http = http;
        this.activatedRoute = activatedRoute;
        this.router = router;
    }
    Object.defineProperty(NSAngular2TokenService.prototype, "currentUserType", {
        get: function () {
            if (this.atCurrentUserType != null)
                return this.atCurrentUserType.name;
            else
                return null;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(NSAngular2TokenService.prototype, "currentUserData", {
        get: function () {
            return this.atCurrentUserData;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(NSAngular2TokenService.prototype, "currentAuthData", {
        get: function () {
            return this.atCurrentAuthData;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(NSAngular2TokenService.prototype, "currentAuthHeaders", {
        get: function () {
            if (this.atCurrentAuthData != null) {
                return new http_1.Headers({
                    'access-token': this.atCurrentAuthData.accessToken,
                    'client': this.atCurrentAuthData.client,
                    'expiry': this.atCurrentAuthData.expiry,
                    'token-type': this.atCurrentAuthData.tokenType,
                    'uid': this.atCurrentAuthData.uid
                });
            }
            return new http_1.Headers;
        },
        enumerable: true,
        configurable: true
    });
    NSAngular2TokenService.prototype.userSignedIn = function () {
        return !!this.atCurrentAuthData;
    };
    NSAngular2TokenService.prototype.canActivate = function () {
        if (this.userSignedIn())
            return true;
        else {
            // Redirect user to sign in if signInRedirect is set
            if (this.router && this.atOptions.signInRedirect)
                this.router.navigate([this.atOptions.signInRedirect]);
            return false;
        }
    };
    // Inital configuration
    NSAngular2TokenService.prototype.init = function (options) {
        var defaultOptions = {
            apiPath: null,
            apiBase: null,
            signInPath: 'auth/sign_in',
            signInRedirect: null,
            signInStoredUrlStorageKey: null,
            signOutPath: 'auth/sign_out',
            validateTokenPath: 'auth/validate_token',
            signOutFailedValidate: false,
            registerAccountPath: 'auth',
            deleteAccountPath: 'auth',
            registerAccountCallback: "",
            updatePasswordPath: 'auth',
            resetPasswordPath: 'auth/password',
            resetPasswordCallback: "",
            userTypes: null,
            oAuthBase: "",
            oAuthPaths: {
                github: 'auth/github'
            },
            oAuthCallbackPath: 'oauth_callback',
            oAuthWindowType: 'newWindow',
            oAuthWindowOptions: null,
            globalOptions: {
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            }
        };
        this.atOptions = Object.assign(defaultOptions, options);
        this.tryLoadAuthData();
    };
    /**
     *
     * Actions
     *
     */
    // Register request
    NSAngular2TokenService.prototype.registerAccount = function (registerData) {
        if (registerData.userType == null)
            this.atCurrentUserType = null;
        else {
            this.atCurrentUserType = this.getUserTypeByName(registerData.userType);
            delete registerData.userType;
        }
        if (registerData.password_confirmation == null &&
            registerData.passwordConfirmation != null) {
            registerData.password_confirmation = registerData.passwordConfirmation;
            delete registerData.passwordConfirmation;
        }
        registerData.confirm_success_url = this.atOptions.registerAccountCallback;
        return this.post(this.getUserPath() + this.atOptions.registerAccountPath, JSON.stringify(registerData));
    };
    // Delete Account
    NSAngular2TokenService.prototype.deleteAccount = function () {
        return this.delete(this.getUserPath() + this.atOptions.deleteAccountPath);
    };
    // Sign in request and set storage
    NSAngular2TokenService.prototype.signIn = function (signInData) {
        var _this = this;
        if (signInData.userType == null)
            this.atCurrentUserType = null;
        else
            this.atCurrentUserType = this.getUserTypeByName(signInData.userType);
        var body = JSON.stringify({
            email: signInData.email,
            password: signInData.password
        });
        var observ = this.post(this.getUserPath() + this.atOptions.signInPath, body);
        observ.subscribe(function (res) { return _this.atCurrentUserData = res.json().data; }, function (_error) { return null; });
        return observ;
    };
    NSAngular2TokenService.prototype.processOAuthCallback = function () {
        this.getAuthDataFromParams();
    };
    // Sign out request and delete storage
    NSAngular2TokenService.prototype.signOut = function () {
        var observ = this.delete(this.getUserPath() + this.atOptions.signOutPath);
        application_settings_1.remove('accessToken');
        application_settings_1.remove('client');
        application_settings_1.remove('expiry');
        application_settings_1.remove('tokenType');
        application_settings_1.remove('uid');
        this.atCurrentAuthData = null;
        this.atCurrentUserType = null;
        this.atCurrentUserData = null;
        return observ;
    };
    // Validate token request
    NSAngular2TokenService.prototype.validateToken = function () {
        var _this = this;
        var observ = this.get(this.getUserPath() + this.atOptions.validateTokenPath);
        observ.subscribe(function (res) { return _this.atCurrentUserData = res.json().data; }, function (error) {
            if (error.status === 401 && _this.atOptions.signOutFailedValidate) {
                _this.signOut();
            }
        });
        return observ;
    };
    // Update password request
    NSAngular2TokenService.prototype.updatePassword = function (updatePasswordData) {
        if (updatePasswordData.userType != null)
            this.atCurrentUserType = this.getUserTypeByName(updatePasswordData.userType);
        var args;
        if (updatePasswordData.passwordCurrent == null) {
            args = {
                password: updatePasswordData.password,
                password_confirmation: updatePasswordData.passwordConfirmation
            };
        }
        else {
            args = {
                current_password: updatePasswordData.passwordCurrent,
                password: updatePasswordData.password,
                password_confirmation: updatePasswordData.passwordConfirmation
            };
        }
        if (updatePasswordData.resetPasswordToken) {
            args.reset_password_token = updatePasswordData.resetPasswordToken;
        }
        var body = JSON.stringify(args);
        return this.put(this.getUserPath() + this.atOptions.updatePasswordPath, body);
    };
    // Reset password request
    NSAngular2TokenService.prototype.resetPassword = function (resetPasswordData) {
        if (resetPasswordData.userType == null)
            this.atCurrentUserType = null;
        else
            this.atCurrentUserType = this.getUserTypeByName(resetPasswordData.userType);
        var body = JSON.stringify({
            email: resetPasswordData.email,
            redirect_url: this.atOptions.resetPasswordCallback
        });
        return this.post(this.getUserPath() + this.atOptions.resetPasswordPath, body);
    };
    /**
     *
     * HTTP Wrappers
     *
     */
    NSAngular2TokenService.prototype.get = function (url, options) {
        return this.request(this.mergeRequestOptionsArgs({
            url: this.getApiPath() + url,
            method: http_1.RequestMethod.Get
        }, options));
    };
    NSAngular2TokenService.prototype.post = function (url, body, options) {
        return this.request(this.mergeRequestOptionsArgs({
            url: this.getApiPath() + url,
            method: http_1.RequestMethod.Post,
            body: body
        }, options));
    };
    NSAngular2TokenService.prototype.put = function (url, body, options) {
        return this.request(this.mergeRequestOptionsArgs({
            url: this.getApiPath() + url,
            method: http_1.RequestMethod.Put,
            body: body
        }, options));
    };
    NSAngular2TokenService.prototype.delete = function (url, options) {
        return this.request(this.mergeRequestOptionsArgs({
            url: this.getApiPath() + url,
            method: http_1.RequestMethod.Delete
        }, options));
    };
    NSAngular2TokenService.prototype.patch = function (url, body, options) {
        return this.request(this.mergeRequestOptionsArgs({
            url: this.getApiPath() + url,
            method: http_1.RequestMethod.Patch,
            body: body
        }, options));
    };
    NSAngular2TokenService.prototype.head = function (path, options) {
        return this.request({
            method: http_1.RequestMethod.Head,
            url: this.getApiPath() + path
        });
    };
    NSAngular2TokenService.prototype.options = function (url, options) {
        return this.request(this.mergeRequestOptionsArgs({
            url: this.getApiPath() + url,
            method: http_1.RequestMethod.Options
        }, options));
    };
    // Construct and send Http request
    NSAngular2TokenService.prototype.request = function (options) {
        var baseRequestOptions;
        var baseHeaders = this.atOptions.globalOptions.headers;
        // Get auth data from local storage
        this.getAuthDataFromStorage();
        // Merge auth headers to request if set
        if (this.atCurrentAuthData != null) {
            Object.assign(baseHeaders, {
                'access-token': this.atCurrentAuthData.accessToken,
                'client': this.atCurrentAuthData.client,
                'expiry': this.atCurrentAuthData.expiry,
                'token-type': this.atCurrentAuthData.tokenType,
                'uid': this.atCurrentAuthData.uid
            });
        }
        baseRequestOptions = new http_1.RequestOptions({
            headers: new http_1.Headers(baseHeaders)
        });
        // Merge standard and custom RequestOptions
        baseRequestOptions = baseRequestOptions.merge(options);
        var response = this.http.request(new http_1.Request(baseRequestOptions)).pipe(operators_1.share());
        this.handleResponse(response);
        return response;
    };
    NSAngular2TokenService.prototype.mergeRequestOptionsArgs = function (options, addOptions) {
        var returnOptions = options;
        if (options)
            Object.assign(returnOptions, addOptions);
        return returnOptions;
    };
    // Check if response is complete and newer, then update storage
    NSAngular2TokenService.prototype.handleResponse = function (response) {
        var _this = this;
        response.subscribe(function (res) {
            _this.getAuthHeadersFromResponse(res);
        }, function (error) {
            _this.getAuthHeadersFromResponse(error);
        });
    };
    /**
     *
     * Get Auth Data
     *
     */
    // Try to load auth data
    NSAngular2TokenService.prototype.tryLoadAuthData = function () {
        var userType = this.getUserTypeByName(application_settings_1.getString('userType'));
        if (userType)
            this.atCurrentUserType = userType;
        this.getAuthDataFromStorage();
        if (this.activatedRoute)
            this.getAuthDataFromParams();
        if (this.atCurrentAuthData)
            this.validateToken();
    };
    // Parse Auth data from response
    NSAngular2TokenService.prototype.getAuthHeadersFromResponse = function (data) {
        var headers = data.headers;
        var authData = {
            accessToken: headers.get('access-token'),
            client: headers.get('client'),
            expiry: headers.get('expiry'),
            tokenType: headers.get('token-type'),
            uid: headers.get('uid')
        };
        this.setAuthData(authData);
    };
    // Parse Auth data from post message
    NSAngular2TokenService.prototype.getAuthDataFromPostMessage = function (data) {
        var authData = {
            accessToken: data['auth_token'],
            client: data['client_id'],
            expiry: data['expiry'],
            tokenType: 'Bearer',
            uid: data['uid']
        };
        this.setAuthData(authData);
    };
    // Try to get auth data from storage.
    NSAngular2TokenService.prototype.getAuthDataFromStorage = function () {
        var authData = {
            accessToken: application_settings_1.getString('accessToken'),
            client: application_settings_1.getString('client'),
            expiry: application_settings_1.getString('expiry'),
            tokenType: application_settings_1.getString('tokenType'),
            uid: application_settings_1.getString('uid')
        };
        if (this.checkAuthData(authData))
            this.atCurrentAuthData = authData;
    };
    // Try to get auth data from url parameters.
    NSAngular2TokenService.prototype.getAuthDataFromParams = function () {
        var _this = this;
        if (this.activatedRoute.queryParams) // Fix for Testing, needs to be removed later
            this.activatedRoute.queryParams.subscribe(function (queryParams) {
                var authData = {
                    accessToken: queryParams['token'] || queryParams['auth_token'],
                    client: queryParams['client_id'],
                    expiry: queryParams['expiry'],
                    tokenType: 'Bearer',
                    uid: queryParams['uid']
                };
                if (_this.checkAuthData(authData))
                    _this.atCurrentAuthData = authData;
            });
    };
    /**
     *
     * Set Auth Data
     *
     */
    // Write auth data to storage
    NSAngular2TokenService.prototype.setAuthData = function (authData) {
        if (this.checkAuthData(authData)) {
            this.atCurrentAuthData = authData;
            application_settings_1.setString('accessToken', authData.accessToken);
            application_settings_1.setString('client', authData.client);
            application_settings_1.setString('expiry', authData.expiry);
            application_settings_1.setString('tokenType', authData.tokenType);
            application_settings_1.setString('uid', authData.uid);
            if (this.atCurrentUserType != null)
                application_settings_1.setString('userType', this.atCurrentUserType.name);
        }
    };
    /**
     *
     * Validate Auth Data
     *
     */
    // Check if auth data complete and if response token is newer
    NSAngular2TokenService.prototype.checkAuthData = function (authData) {
        if (authData.accessToken != null &&
            authData.client != null &&
            authData.expiry != null &&
            authData.tokenType != null &&
            authData.uid != null) {
            if (this.atCurrentAuthData != null)
                return authData.expiry >= this.atCurrentAuthData.expiry;
            else
                return true;
        }
        else {
            return false;
        }
    };
    /**
     *
     * Construct Paths / Urls
     *
     */
    NSAngular2TokenService.prototype.getUserPath = function () {
        if (this.atCurrentUserType == null)
            return '';
        else
            return this.atCurrentUserType.path + '/';
    };
    NSAngular2TokenService.prototype.getApiPath = function () {
        var constructedPath = '';
        if (this.atOptions.apiBase != null)
            constructedPath += this.atOptions.apiBase + '/';
        if (this.atOptions.apiPath != null)
            constructedPath += this.atOptions.apiPath + '/';
        return constructedPath;
    };
    NSAngular2TokenService.prototype.getOAuthPath = function (oAuthType) {
        var oAuthPath;
        oAuthPath = this.atOptions.oAuthPaths[oAuthType];
        if (oAuthPath == null)
            oAuthPath = "/auth/" + oAuthType;
        return oAuthPath;
    };
    NSAngular2TokenService.prototype.getOAuthUrl = function (oAuthPath, callbackUrl, windowType) {
        var url;
        url = this.atOptions.oAuthBase + "/" + oAuthPath;
        url += "?omniauth_window_type=" + windowType;
        url += "&auth_origin_url=" + encodeURIComponent(callbackUrl);
        if (this.atCurrentUserType != null)
            url += "&resource_class=" + this.atCurrentUserType.name;
        return url;
    };
    /**
     *
     * OAuth
     *
     */
    NSAngular2TokenService.prototype.requestCredentialsViaPostMessage = function (authWindow) {
        var pollerObserv = rxjs_1.interval(500);
        var responseObserv = rxjs_1.fromEvent(window, 'message').pipe(operators_1.pluck('data'), operators_1.filter(this.oAuthWindowResponseFilter));
        var responseSubscription = responseObserv.subscribe(this.getAuthDataFromPostMessage.bind(this));
        var pollerSubscription = pollerObserv.subscribe(function () {
            if (authWindow.closed)
                pollerSubscription.unsubscribe();
            else
                authWindow.postMessage('requestCredentials', '*');
        });
        return responseObserv;
    };
    NSAngular2TokenService.prototype.oAuthWindowResponseFilter = function (data) {
        if (data.message == 'deliverCredentials' || data.message == 'authFailure')
            return data;
    };
    /**
     *
     * Utilities
     *
     */
    // Match user config by user config name
    NSAngular2TokenService.prototype.getUserTypeByName = function (name) {
        if (name == null || this.atOptions.userTypes == null)
            return null;
        return this.atOptions.userTypes.find(function (userType) { return userType.name === name; });
    };
    NSAngular2TokenService = __decorate([
        core_1.Injectable(),
        __param(1, core_1.Optional()),
        __param(2, core_1.Optional()),
        __metadata("design:paramtypes", [http_1.Http,
            router_1.ActivatedRoute,
            router_1.Router])
    ], NSAngular2TokenService);
    return NSAngular2TokenService;
}());
exports.NSAngular2TokenService = NSAngular2TokenService;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibnMtYW5ndWxhcjItdG9rZW4uc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIm5zLWFuZ3VsYXIyLXRva2VuLnNlcnZpY2UudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSxzQ0FBcUQ7QUFDckQsMENBQXNFO0FBQ3RFLHNDQVF1QjtBQUV2Qiw2QkFBdUQ7QUFDdkQsNENBQXNEO0FBYXRELDZEQUFvRTtBQUdwRTtJQW9DSSxnQ0FDWSxJQUFVLEVBQ0UsY0FBOEIsRUFDOUIsTUFBYztRQUYxQixTQUFJLEdBQUosSUFBSSxDQUFNO1FBQ0UsbUJBQWMsR0FBZCxjQUFjLENBQWdCO1FBQzlCLFdBQU0sR0FBTixNQUFNLENBQVE7SUFDbEMsQ0FBQztJQXRDTCxzQkFBSSxtREFBZTthQUFuQjtZQUNJLElBQUksSUFBSSxDQUFDLGlCQUFpQixJQUFJLElBQUk7Z0JBQzlCLE9BQU8sSUFBSSxDQUFDLGlCQUFpQixDQUFDLElBQUksQ0FBQzs7Z0JBRW5DLE9BQU8sSUFBSSxDQUFDO1FBQ3BCLENBQUM7OztPQUFBO0lBRUQsc0JBQUksbURBQWU7YUFBbkI7WUFDSSxPQUFPLElBQUksQ0FBQyxpQkFBaUIsQ0FBQztRQUNsQyxDQUFDOzs7T0FBQTtJQUVELHNCQUFJLG1EQUFlO2FBQW5CO1lBQ0ksT0FBTyxJQUFJLENBQUMsaUJBQWlCLENBQUM7UUFDbEMsQ0FBQzs7O09BQUE7SUFFRCxzQkFBSSxzREFBa0I7YUFBdEI7WUFDSSxJQUFJLElBQUksQ0FBQyxpQkFBaUIsSUFBSSxJQUFJLEVBQUU7Z0JBQ2hDLE9BQU8sSUFBSSxjQUFPLENBQUM7b0JBQ2YsY0FBYyxFQUFFLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxXQUFXO29CQUNsRCxRQUFRLEVBQVEsSUFBSSxDQUFDLGlCQUFpQixDQUFDLE1BQU07b0JBQzdDLFFBQVEsRUFBUSxJQUFJLENBQUMsaUJBQWlCLENBQUMsTUFBTTtvQkFDN0MsWUFBWSxFQUFJLElBQUksQ0FBQyxpQkFBaUIsQ0FB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R0FBakMsVUFBa0MsSUFBUztRQUN2QyxJQUFHLElBQUksQ0FBQyxPQUFPLElBQUksb0JBQW9CLElBQUksSUFBSSxDQUFDLE9BQU8sSUFBSSxhQUFhO1lBQ3BFLE9BQU8sSUFBSSxDQUFDO0lBQ3BCLENBQUM7SUFFRDs7OztPQUlHO0lBRUgsd0NBQXdDO0lBQ2hDLGtEQUFpQixHQUF6QixVQUEwQixJQUFZO1FBQ2xDLElBQUksSUFBSSxJQUFJLElBQUksSUFBSSxJQUFJLENBQUMsU0FBUyxDQUFDLFNBQVMsSUFBSSxJQUFJO1lBQ2hELE9BQU8sSUFBSSxDQUFDO1FBRWhCLE9BQU8sSUFBSSxDQUFDLFNBQVMsQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUNoQyxVQUFBLFFBQVEsSUFBSSxPQUFBLFFBQVEsQ0FBQyxJQUFJLEtBQUssSUFBSSxFQUF0QixDQUFzQixDQUNyQyxDQUFDO0lBQ04sQ0FBQztJQXJrQlEsc0JBQXNCO1FBRGxDLGlCQUFVLEVBQUU7UUF1Q0osV0FBQSxlQUFRLEVBQUUsQ0FBQTtRQUNWLFdBQUEsZUFBUSxFQUFFLENBQUE7eUNBRkcsV0FBSTtZQUNrQix1QkFBYztZQUN0QixlQUFNO09BdkM3QixzQkFBc0IsQ0Fza0JsQztJQUFELDZCQUFDO0NBQUEsQUF0a0JELElBc2tCQztBQXRrQlksd0RBQXNCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSwgT3B0aW9uYWwgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IEFjdGl2YXRlZFJvdXRlLCBSb3V0ZXIsIENhbkFjdGl2YXRlIH0gZnJvbSAnQGFuZ3VsYXIvcm91dGVyJztcbmltcG9ydCB7XG4gICAgSHR0cCxcbiAgICBSZXNwb25zZSxcbiAgICBIZWFkZXJzLFxuICAgIFJlcXVlc3QsXG4gICAgUmVxdWVzdE1ldGhvZCxcbiAgICBSZXF1ZXN0T3B0aW9ucyxcbiAgICBSZXF1ZXN0T3B0aW9uc0FyZ3Ncbn0gZnJvbSAnQGFuZ3VsYXIvaHR0cCc7XG5cbmltcG9ydCB7IE9ic2VydmFibGUsIGludGVydmFsLCBmcm9tRXZlbnQgfSBmcm9tICdyeGpzJztcbmltcG9ydCB7IHNoYXJlLCBwbHVjaywgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuXG5pbXBvcnQge1xuICAgIFNpZ25JbkRhdGEsXG4gICAgUmVnaXN0ZXJEYXRhLFxuICAgIFVwZGF0ZVBhc3N3b3JkRGF0YSxcbiAgICBSZXNldFBhc3N3b3JkRGF0YSxcbiAgICBVc2VyVHlwZSxcbiAgICBVc2VyRGF0YSxcbiAgICBBdXRoRGF0YSxcbiAgICBBbmd1bGFyMlRva2VuT3B0aW9uc1xufSBmcm9tICcuL25zLWFuZ3VsYXIyLXRva2VuLm1vZGVsJztcblxuaW1wb3J0IHsgZ2V0U3RyaW5nLCBzZXRTdHJpbmcsIHJlbW92ZSB9IGZyb20gXCJhcHBsaWNhdGlvbi1zZXR0aW5nc1wiO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgTlNBbmd1bGFyMlRva2VuU2VydmljZSBpbXBsZW1lbnRzIENhbkFjdGl2YXRlIHtcblxuICAgIGdldCBjdXJyZW50VXNlclR5cGUoKTogc3RyaW5nIHtcbiAgICAgICAgaWYgKHRoaXMuYXRDdXJyZW50VXNlclR5cGUgIT0gbnVsbClcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmF0Q3VycmVudFVzZXJUeXBlLm5hbWU7XG4gICAgICAgIGVsc2VcbiAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgIH1cblxuICAgIGdldCBjdXJyZW50VXNlckRhdGEoKTogVXNlckRhdGEge1xuICAgICAgICByZXR1cm4gdGhpcy5hdEN1cnJlbnRVc2VyRGF0YTtcbiAgICB9XG5cbiAgICBnZXQgY3VycmVudEF1dGhEYXRhKCk6IEF1dGhEYXRhIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXRDdXJyZW50QXV0aERhdGE7XG4gICAgfVxuXG4gICAgZ2V0IGN1cnJlbnRBdXRoSGVhZGVycygpOiBIZWFkZXJzIHtcbiAgICAgICAgaWYgKHRoaXMuYXRDdXJyZW50QXV0aERhdGEgIT0gbnVsbCkge1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBIZWFkZXJzKHtcbiAgICAgICAgICAgICAgICAnYWNjZXNzLXRva2VuJzogdGhpcy5hdEN1cnJlbnRBdXRoRGF0YS5hY2Nlc3NUb2tlbixcbiAgICAgICAgICAgICAgICAnY2xpZW50JzogICAgICAgdGhpcy5hdEN1cnJlbnRBdXRoRGF0YS5jbGllbnQsXG4gICAgICAgICAgICAgICAgJ2V4cGlyeSc6ICAgICAgIHRoaXMuYXRDdXJyZW50QXV0aERhdGEuZXhwaXJ5LFxuICAgICAgICAgICAgICAgICd0b2tlbi10eXBlJzogICB0aGlzLmF0Q3VycmVudEF1dGhEYXRhLnRva2VuVHlwZSxcbiAgICAgICAgICAgICAgICAndWlkJzogICAgICAgICAgdGhpcy5hdEN1cnJlbnRBdXRoRGF0YS51aWRcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIG5ldyBIZWFkZXJzO1xuICAgIH1cblxuICAgIHByaXZhdGUgYXRPcHRpb25zOiBBbmd1bGFyMlRva2VuT3B0aW9ucztcbiAgICBwcml2YXRlIGF0Q3VycmVudFVzZXJUeXBlOiBVc2VyVHlwZTtcbiAgICBwcml2YXRlIGF0Q3VycmVudEF1dGhEYXRhOiBBdXRoRGF0YTtcbiAgICBwcml2YXRlIGF0Q3VycmVudFVzZXJEYXRhOiBVc2VyRGF0YTtcblxuICAgIGNvbnN0cnVjdG9yKFxuICAgICAgICBwcml2YXRlIGh0dHA6IEh0dHAsXG4gICAgICAgIEBPcHRpb25hbCgpIHByaXZhdGUgYWN0aXZhdGVkUm91dGU6IEFjdGl2YXRlZFJvdXRlLFxuICAgICAgICBAT3B0aW9uYWwoKSBwcml2YXRlIHJvdXRlcjogUm91dGVyXG4gICAgKSB7IH1cblxuICAgIHVzZXJTaWduZWRJbigpOiBib29sZWFuIHtcbiAgICAgICAgcmV0dXJuICEhdGhpcy5hdEN1cnJlbnRBdXRoRGF0YTtcbiAgICB9XG5cbiAgICBjYW5BY3RpdmF0ZSgpOiBib29sZWFuIHtcbiAgICAgICAgaWYgKHRoaXMudXNlclNpZ25lZEluKCkpXG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgZWxzZSB7XG5cbiAgICAgICAgICAgIC8vIFJlZGlyZWN0IHVzZXIgdG8gc2lnbiBpbiBpZiBzaWduSW5SZWRpcmVjdCBpcyBzZXRcbiAgICAgICAgICAgIGlmKHRoaXMucm91dGVyICYmIHRoaXMuYXRPcHRpb25zLnNpZ25JblJlZGlyZWN0KVxuICAgICAgICAgICAgICAgIHRoaXMucm91dGVyLm5hdmlnYXRlKFt0aGlzLmF0T3B0aW9ucy5zaWduSW5SZWRpcmVjdF0pO1xuXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBJbml0YWwgY29uZmlndXJhdGlvblxuICAgIGluaXQob3B0aW9ucz86IEFuZ3VsYXIyVG9rZW5PcHRpb25zKSB7XG5cbiAgICAgICAgbGV0IGRlZmF1bHRPcHRpb25zOiBBbmd1bGFyMlRva2VuT3B0aW9ucyA9IHtcbiAgICAgICAgICAgIGFwaVBhdGg6ICAgICAgICAgICAgICAgICAgICBudWxsLFxuICAgICAgICAgICAgYXBpQmFzZTogICAgICAgICAgICAgICAgICAgIG51bGwsXG5cbiAgICAgICAgICAgIHNpZ25JblBhdGg6ICAgICAgICAgICAgICAgICAnYXV0aC9zaWduX2luJyxcbiAgICAgICAgICAgIHNpZ25JblJlZGlyZWN0OiAgICAgICAgICAgICBudWxsLFxuICAgICAgICAgICAgc2lnbkluU3RvcmVkVXJsU3RvcmFnZUtleTogIG51bGwsXG5cbiAgICAgICAgICAgIHNpZ25PdXRQYXRoOiAgICAgICAgICAgICAgICAnYXV0aC9zaWduX291dCcsXG4gICAgICAgICAgICB2YWxpZGF0ZVRva2VuUGF0aDogICAgICAgICAgJ2F1dGgvdmFsaWRhdGVfdG9rZW4nLFxuICAgICAgICAgICAgc2lnbk91dEZhaWxlZFZhbGlkYXRlOiAgICAgIGZhbHNlLFxuXG4gICAgICAgICAgICByZWdpc3RlckFjY291bnRQYXRoOiAgICAgICAgJ2F1dGgnLFxuICAgICAgICAgICAgZGVsZXRlQWNjb3VudFBhdGg6ICAgICAgICAgICdhdXRoJyxcbiAgICAgICAgICAgIHJlZ2lzdGVyQWNjb3VudENhbGxiYWNrOiAgICBcIlwiLFxuXG4gICAgICAgICAgICB1cGRhdGVQYXNzd29yZFBhdGg6ICAgICAgICAgJ2F1dGgnLFxuXG4gICAgICAgICAgICByZXNldFBhc3N3b3JkUGF0aDogICAgICAgICAgJ2F1dGgvcGFzc3dvcmQnLFxuICAgICAgICAgICAgcmVzZXRQYXNzd29yZENhbGxiYWNrOiAgICAgIFwiXCIsXG5cbiAgICAgICAgICAgIHVzZXJUeXBlczogICAgICAgICAgICAgICAgICBudWxsLFxuXG4gICAgICAgICAgICBvQXV0aEJhc2U6ICAgICAgICAgICAgICAgICAgXCJcIixcbiAgICAgICAgICAgIG9BdXRoUGF0aHM6IHtcbiAgICAgICAgICAgICAgICBnaXRodWI6ICAgICAgICAgICAgICAgICAnYXV0aC9naXRodWInXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgb0F1dGhDYWxsYmFja1BhdGg6ICAgICAgICAgICdvYXV0aF9jYWxsYmFjaycsXG4gICAgICAgICAgICBvQXV0aFdpbmRvd1R5cGU6ICAgICAgICAgICAgJ25ld1dpbmRvdycsXG4gICAgICAgICAgICBvQXV0aFdpbmRvd09wdGlvbnM6ICAgICAgICAgbnVsbCxcblxuICAgICAgICAgICAgZ2xvYmFsT3B0aW9uczoge1xuICAgICAgICAgICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICAgICAgICAgICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyxcbiAgICAgICAgICAgICAgICAgICAgJ0FjY2VwdCc6ICAgICAgICdhcHBsaWNhdGlvbi9qc29uJ1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmF0T3B0aW9ucyA9ICg8YW55Pk9iamVjdCkuYXNzaWduKGRlZmF1bHRPcHRpb25zLCBvcHRpb25zKTtcblxuICAgICAgICB0aGlzLnRyeUxvYWRBdXRoRGF0YSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqXG4gICAgICogQWN0aW9uc1xuICAgICAqXG4gICAgICovXG5cbiAgICAvLyBSZWdpc3RlciByZXF1ZXN0XG4gICAgcmVnaXN0ZXJBY2NvdW50KHJlZ2lzdGVyRGF0YTogUmVnaXN0ZXJEYXRhKTogT2JzZXJ2YWJsZTxSZXNwb25zZT4ge1xuXG4gICAgICAgIGlmIChyZWdpc3RlckRhdGEudXNlclR5cGUgPT0gbnVsbClcbiAgICAgICAgICAgIHRoaXMuYXRDdXJyZW50VXNlclR5cGUgPSBudWxsO1xuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHRoaXMuYXRDdXJyZW50VXNlclR5cGUgPSB0aGlzLmdldFVzZXJUeXBlQnlOYW1lKHJlZ2lzdGVyRGF0YS51c2VyVHlwZSk7XG4gICAgICAgICAgICBkZWxldGUgcmVnaXN0ZXJEYXRhLnVzZXJUeXBlO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKFxuICAgICAgICAgICAgcmVnaXN0ZXJEYXRhLnBhc3N3b3JkX2NvbmZpcm1hdGlvbiA9PSBudWxsICYmIFxuICAgICAgICAgICAgcmVnaXN0ZXJEYXRhLnBhc3N3b3JkQ29uZmlybWF0aW9uICE9IG51bGxcbiAgICAgICAgKSB7XG4gICAgICAgICAgICByZWdpc3RlckRhdGEucGFzc3dvcmRfY29uZmlybWF0aW9uICA9IHJlZ2lzdGVyRGF0YS5wYXNzd29yZENvbmZpcm1hdGlvbjtcbiAgICAgICAgICAgIGRlbGV0ZSByZWdpc3RlckRhdGEucGFzc3dvcmRDb25maXJtYXRpb247XG4gICAgICAgIH1cblxuICAgICAgICByZWdpc3RlckRhdGEuY29uZmlybV9zdWNjZXNzX3VybCAgICA9IHRoaXMuYXRPcHRpb25zLnJlZ2lzdGVyQWNjb3VudENhbGxiYWNrO1xuXG4gICAgICAgIHJldHVybiB0aGlzLnBvc3QodGhpcy5nZXRVc2VyUGF0aCgpICsgdGhpcy5hdE9wdGlvbnMucmVnaXN0ZXJBY2NvdW50UGF0aCwgSlNPTi5zdHJpbmdpZnkocmVnaXN0ZXJEYXRhKSk7XG4gICAgfVxuXG4gICAgLy8gRGVsZXRlIEFjY291bnRcbiAgICBkZWxldGVBY2NvdW50KCk6IE9ic2VydmFibGU8UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZGVsZXRlKHRoaXMuZ2V0VXNlclBhdGgoKSArIHRoaXMuYXRPcHRpb25zLmRlbGV0ZUFjY291bnRQYXRoKTtcbiAgICB9XG5cbiAgICAvLyBTaWduIGluIHJlcXVlc3QgYW5kIHNldCBzdG9yYWdlXG4gICAgc2lnbkluKHNpZ25JbkRhdGE6IFNpZ25JbkRhdGEpOiBPYnNlcnZhYmxlPFJlc3BvbnNlPiB7XG5cbiAgICAgICAgaWYgKHNpZ25JbkRhdGEudXNlclR5cGUgPT0gbnVsbClcbiAgICAgICAgICAgIHRoaXMuYXRDdXJyZW50VXNlclR5cGUgPSBudWxsO1xuICAgICAgICBlbHNlXG4gICAgICAgICAgICB0aGlzLmF0Q3VycmVudFVzZXJUeXBlID0gdGhpcy5nZXRVc2VyVHlwZUJ5TmFtZShzaWduSW5EYXRhLnVzZXJUeXBlKTtcblxuICAgICAgICBsZXQgYm9keSA9IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICAgIGVtYWlsOiAgICAgIHNpZ25JbkRhdGEuZW1haWwsXG4gICAgICAgICAgICBwYXNzd29yZDogICBzaWduSW5EYXRhLnBhc3N3b3JkXG4gICAgICAgIH0pO1xuXG4gICAgICAgIGxldCBvYnNlcnYgPSB0aGlzLnBvc3QodGhpcy5nZXRVc2VyUGF0aCgpICsgdGhpcy5hdE9wdGlvbnMuc2lnbkluUGF0aCwgYm9keSk7XG5cbiAgICAgICAgb2JzZXJ2LnN1YnNjcmliZShyZXMgPT4gdGhpcy5hdEN1cnJlbnRVc2VyRGF0YSA9IHJlcy5qc29uKCkuZGF0YSwgX2Vycm9yID0+IG51bGwpO1xuXG4gICAgICAgIHJldHVybiBvYnNlcnY7XG4gICAgfVxuXG5cbiAgICBwcm9jZXNzT0F1dGhDYWxsYmFjaygpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5nZXRBdXRoRGF0YUZyb21QYXJhbXMoKTtcbiAgICB9XG5cbiAgICAvLyBTaWduIG91dCByZXF1ZXN0IGFuZCBkZWxldGUgc3RvcmFnZVxuICAgIHNpZ25PdXQoKTogT2JzZXJ2YWJsZTxSZXNwb25zZT4ge1xuICAgICAgICBsZXQgb2JzZXJ2ID0gdGhpcy5kZWxldGUodGhpcy5nZXRVc2VyUGF0aCgpICsgdGhpcy5hdE9wdGlvbnMuc2lnbk91dFBhdGgpO1xuXG4gICAgICAgIHJlbW92ZSgnYWNjZXNzVG9rZW4nKTtcbiAgICAgICAgcmVtb3ZlKCdjbGllbnQnKTtcbiAgICAgICAgcmVtb3ZlKCdleHBpcnknKTtcbiAgICAgICAgcmVtb3ZlKCd0b2tlblR5cGUnKTtcbiAgICAgICAgcmVtb3ZlKCd1aWQnKTtcblxuICAgICAgICB0aGlzLmF0Q3VycmVudEF1dGhEYXRhID0gbnVsbDtcbiAgICAgICAgdGhpcy5hdEN1cnJlbnRVc2VyVHlwZSA9IG51bGw7XG4gICAgICAgIHRoaXMuYXRDdXJyZW50VXNlckRhdGEgPSBudWxsO1xuXG4gICAgICAgIHJldHVybiBvYnNlcnY7XG4gICAgfVxuXG4gICAgLy8gVmFsaWRhdGUgdG9rZW4gcmVxdWVzdFxuICAgIHZhbGlkYXRlVG9rZW4oKTogT2JzZXJ2YWJsZTxSZXNwb25zZT4ge1xuICAgICAgICBsZXQgb2JzZXJ2ID0gdGhpcy5nZXQodGhpcy5nZXRVc2VyUGF0aCgpICsgdGhpcy5hdE9wdGlvbnMudmFsaWRhdGVUb2tlblBhdGgpO1xuXG4gICAgICAgIG9ic2Vydi5zdWJzY3JpYmUoXG4gICAgICAgICAgICByZXMgPT4gdGhpcy5hdEN1cnJlbnRVc2VyRGF0YSA9IHJlcy5qc29uKCkuZGF0YSxcbiAgICAgICAgICAgIGVycm9yID0+IHtcbiAgICAgICAgICAgICAgICBpZiAoZXJyb3Iuc3RhdHVzID09PSA0MDEgJiYgdGhpcy5hdE9wdGlvbnMuc2lnbk91dEZhaWxlZFZhbGlkYXRlKSB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuc2lnbk91dCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgIHJldHVybiBvYnNlcnY7XG4gICAgfVxuXG4gICAgLy8gVXBkYXRlIHBhc3N3b3JkIHJlcXVlc3RcbiAgICB1cGRhdGVQYXNzd29yZCh1cGRhdGVQYXNzd29yZERhdGE6IFVwZGF0ZVBhc3N3b3JkRGF0YSk6IE9ic2VydmFibGU8UmVzcG9uc2U+IHtcblxuICAgICAgICBpZiAodXBkYXRlUGFzc3dvcmREYXRhLnVzZXJUeXBlICE9IG51bGwpXG4gICAgICAgICAgICB0aGlzLmF0Q3VycmVudFVzZXJUeXBlID0gdGhpcy5nZXRVc2VyVHlwZUJ5TmFtZSh1cGRhdGVQYXNzd29yZERhdGEudXNlclR5cGUpO1xuXG4gICAgICAgIGxldCBhcmdzOiBhbnk7XG5cbiAgICAgICAgaWYgKHVwZGF0ZVBhc3N3b3JkRGF0YS5wYXNzd29yZEN1cnJlbnQgPT0gbnVsbCkge1xuICAgICAgICAgICAgYXJncyA9IHtcbiAgICAgICAgICAgICAgICBwYXNzd29yZDogICAgICAgICAgICAgICB1cGRhdGVQYXNzd29yZERhdGEucGFzc3dvcmQsXG4gICAgICAgICAgICAgICAgcGFzc3dvcmRfY29uZmlybWF0aW9uOiAgdXBkYXRlUGFzc3dvcmREYXRhLnBhc3N3b3JkQ29uZmlybWF0aW9uXG4gICAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBhcmdzID0ge1xuICAgICAgICAgICAgICAgIGN1cnJlbnRfcGFzc3dvcmQ6ICAgICAgIHVwZGF0ZVBhc3N3b3JkRGF0YS5wYXNzd29yZEN1cnJlbnQsXG4gICAgICAgICAgICAgICAgcGFzc3dvcmQ6ICAgICAgICAgICAgICAgdXBkYXRlUGFzc3dvcmREYXRhLnBhc3N3b3JkLFxuICAgICAgICAgICAgICAgIHBhc3N3b3JkX2NvbmZpcm1hdGlvbjogIHVwZGF0ZVBhc3N3b3JkRGF0YS5wYXNzd29yZENvbmZpcm1hdGlvblxuICAgICAgICAgICAgfTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh1cGRhdGVQYXNzd29yZERhdGEucmVzZXRQYXNzd29yZFRva2VuKSB7XG4gICAgICAgICAgICBhcmdzLnJlc2V0X3Bhc3N3b3JkX3Rva2VuID0gdXBkYXRlUGFzc3dvcmREYXRhLnJlc2V0UGFzc3dvcmRUb2tlbjtcbiAgICAgICAgfVxuXG4gICAgICAgIGxldCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoYXJncyk7XG4gICAgICAgIHJldHVybiB0aGlzLnB1dCh0aGlzLmdldFVzZXJQYXRoKCkgKyB0aGlzLmF0T3B0aW9ucy51cGRhdGVQYXNzd29yZFBhdGgsIGJvZHkpO1xuICAgIH1cblxuICAgIC8vIFJlc2V0IHBhc3N3b3JkIHJlcXVlc3RcbiAgICByZXNldFBhc3N3b3JkKHJlc2V0UGFzc3dvcmREYXRhOiBSZXNldFBhc3N3b3JkRGF0YSk6IE9ic2VydmFibGU8UmVzcG9uc2U+IHtcblxuICAgICAgICBpZiAocmVzZXRQYXNzd29yZERhdGEudXNlclR5cGUgPT0gbnVsbClcbiAgICAgICAgICAgIHRoaXMuYXRDdXJyZW50VXNlclR5cGUgPSBudWxsO1xuICAgICAgICBlbHNlXG4gICAgICAgICAgICB0aGlzLmF0Q3VycmVudFVzZXJUeXBlID0gdGhpcy5nZXRVc2VyVHlwZUJ5TmFtZShyZXNldFBhc3N3b3JkRGF0YS51c2VyVHlwZSk7XG5cbiAgICAgICAgbGV0IGJvZHkgPSBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgICBlbWFpbDogICAgICAgICAgcmVzZXRQYXNzd29yZERhdGEuZW1haWwsXG4gICAgICAgICAgICByZWRpcmVjdF91cmw6ICAgdGhpcy5hdE9wdGlvbnMucmVzZXRQYXNzd29yZENhbGxiYWNrXG4gICAgICAgIH0pO1xuXG4gICAgICAgIHJldHVybiB0aGlzLnBvc3QodGhpcy5nZXRVc2VyUGF0aCgpICsgdGhpcy5hdE9wdGlvbnMucmVzZXRQYXNzd29yZFBhdGgsIGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqXG4gICAgICogSFRUUCBXcmFwcGVyc1xuICAgICAqXG4gICAgICovXG5cbiAgICBnZXQodXJsOiBzdHJpbmcsIG9wdGlvbnM/OiBSZXF1ZXN0T3B0aW9uc0FyZ3MpOiBPYnNlcnZhYmxlPFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnJlcXVlc3QodGhpcy5tZXJnZVJlcXVlc3RPcHRpb25zQXJncyh7XG4gICAgICAgICAgICB1cmw6ICAgIHRoaXMuZ2V0QXBpUGF0aCgpICsgdXJsLFxuICAgICAgICAgICAgbWV0aG9kOiBSZXF1ZXN0TWV0aG9kLkdldFxuICAgICAgICB9LCBvcHRpb25zKSk7XG4gICAgfVxuXG4gICAgcG9zdCh1cmw6IHN0cmluZywgYm9keTogYW55LCBvcHRpb25zPzogUmVxdWVzdE9wdGlvbnNBcmdzKTogT2JzZXJ2YWJsZTxSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5yZXF1ZXN0KHRoaXMubWVyZ2VSZXF1ZXN0T3B0aW9uc0FyZ3Moe1xuICAgICAgICAgICAgdXJsOiAgICB0aGlzLmdldEFwaVBhdGgoKSArIHVybCxcbiAgICAgICAgICAgIG1ldGhvZDogUmVxdWVzdE1ldGhvZC5Qb3N0LFxuICAgICAgICAgICAgYm9keTogICBib2R5XG4gICAgICAgIH0sIG9wdGlvbnMpKTtcbiAgICB9XG5cbiAgICBwdXQodXJsOiBzdHJpbmcsIGJvZHk6IGFueSwgb3B0aW9ucz86IFJlcXVlc3RPcHRpb25zQXJncyk6IE9ic2VydmFibGU8UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucmVxdWVzdCh0aGlzLm1lcmdlUmVxdWVzdE9wdGlvbnNBcmdzKHtcbiAgICAgICAgICAgIHVybDogICAgdGhpcy5nZXRBcGlQYXRoKCkgKyB1cmwsXG4gICAgICAgICAgICBtZXRob2Q6IFJlcXVlc3RNZXRob2QuUHV0LFxuICAgICAgICAgICAgYm9keTogICBib2R5XG4gICAgICAgIH0sIG9wdGlvbnMpKTtcbiAgICB9XG5cbiAgICBkZWxldGUodXJsOiBzdHJpbmcsIG9wdGlvbnM/OiBSZXF1ZXN0T3B0aW9uc0FyZ3MpOiBPYnNlcnZhYmxlPFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnJlcXVlc3QodGhpcy5tZXJnZVJlcXVlc3RPcHRpb25zQXJncyh7XG4gICAgICAgICAgICB1cmw6ICAgIHRoaXMuZ2V0QXBpUGF0aCgpICsgdXJsLFxuICAgICAgICAgICAgbWV0aG9kOiBSZXF1ZXN0TWV0aG9kLkRlbGV0ZVxuICAgICAgICB9LCBvcHRpb25zKSk7XG4gICAgfVxuXG4gICAgcGF0Y2godXJsOiBzdHJpbmcsIGJvZHk6IGFueSwgb3B0aW9ucz86IFJlcXVlc3RPcHRpb25zQXJncyk6IE9ic2VydmFibGU8UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucmVxdWVzdCh0aGlzLm1lcmdlUmVxdWVzdE9wdGlvbnNBcmdzKHtcbiAgICAgICAgICAgIHVybDogICAgdGhpcy5nZXRBcGlQYXRoKCkgKyB1cmwsXG4gICAgICAgICAgICBtZXRob2Q6IFJlcXVlc3RNZXRob2QuUGF0Y2gsXG4gICAgICAgICAgICBib2R5OiAgIGJvZHlcbiAgICAgICAgfSwgb3B0aW9ucykpO1xuICAgIH1cblxuICAgIGhlYWQocGF0aDogc3RyaW5nLCBvcHRpb25zPzogUmVxdWVzdE9wdGlvbnNBcmdzKTogT2JzZXJ2YWJsZTxSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5yZXF1ZXN0KHtcbiAgICAgICAgICAgIG1ldGhvZDogUmVxdWVzdE1ldGhvZC5IZWFkLFxuICAgICAgICAgICAgdXJsOiAgICB0aGlzLmdldEFwaVBhdGgoKSArIHBhdGhcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgb3B0aW9ucyh1cmw6IHN0cmluZywgb3B0aW9ucz86IFJlcXVlc3RPcHRpb25zQXJncyk6IE9ic2VydmFibGU8UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucmVxdWVzdCh0aGlzLm1lcmdlUmVxdWVzdE9wdGlvbnNBcmdzKHtcbiAgICAgICAgICAgIHVybDogICAgdGhpcy5nZXRBcGlQYXRoKCkgKyB1cmwsXG4gICAgICAgICAgICBtZXRob2Q6IFJlcXVlc3RNZXRob2QuT3B0aW9uc1xuICAgICAgICB9LCBvcHRpb25zKSk7XG4gICAgfVxuXG4gICAgLy8gQ29uc3RydWN0IGFuZCBzZW5kIEh0dHAgcmVxdWVzdFxuICAgIHJlcXVlc3Qob3B0aW9uczogUmVxdWVzdE9wdGlvbnNBcmdzKTogT2JzZXJ2YWJsZTxSZXNwb25zZT4ge1xuXG4gICAgICAgIGxldCBiYXNlUmVxdWVzdE9wdGlvbnM6IFJlcXVlc3RPcHRpb25zO1xuICAgICAgICBsZXQgYmFzZUhlYWRlcnM6ICAgICAgICB7IFtrZXk6c3RyaW5nXTogc3RyaW5nOyB9ID0gdGhpcy5hdE9wdGlvbnMuZ2xvYmFsT3B0aW9ucy5oZWFkZXJzO1xuXG4gICAgICAgIC8vIEdldCBhdXRoIGRhdGEgZnJvbSBsb2NhbCBzdG9yYWdlXG4gICAgICAgIHRoaXMuZ2V0QXV0aERhdGFGcm9tU3RvcmFnZSgpO1xuICAgICAgICBcbiAgICAgICAgLy8gTWVyZ2UgYXV0aCBoZWFkZXJzIHRvIHJlcXVlc3QgaWYgc2V0XG4gICAgICAgIGlmICh0aGlzLmF0Q3VycmVudEF1dGhEYXRhICE9IG51bGwpIHtcbiAgICAgICAgICAgICg8YW55Pk9iamVjdCkuYXNzaWduKGJhc2VIZWFkZXJzLCB7XG4gICAgICAgICAgICAgICAgJ2FjY2Vzcy10b2tlbic6IHRoaXMuYXRDdXJyZW50QXV0aERhdGEuYWNjZXNzVG9rZW4sXG4gICAgICAgICAgICAgICAgJ2NsaWVudCc6ICAgICAgIHRoaXMuYXRDdXJyZW50QXV0aERhdGEuY2xpZW50LFxuICAgICAgICAgICAgICAgICdleHBpcnknOiAgICAgICB0aGlzLmF0Q3VycmVudEF1dGhEYXRhLmV4cGlyeSxcbiAgICAgICAgICAgICAgICAndG9rZW4tdHlwZSc6ICAgdGhpcy5hdEN1cnJlbnRBdXRoRGF0YS50b2tlblR5cGUsXG4gICAgICAgICAgICAgICAgJ3VpZCc6ICAgICAgICAgIHRoaXMuYXRDdXJyZW50QXV0aERhdGEudWlkXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIGJhc2VSZXF1ZXN0T3B0aW9ucyA9IG5ldyBSZXF1ZXN0T3B0aW9ucyh7XG4gICAgICAgICAgICBoZWFkZXJzOiBuZXcgSGVhZGVycyhiYXNlSGVhZGVycylcbiAgICAgICAgfSk7XG5cbiAgICAgICAgLy8gTWVyZ2Ugc3RhbmRhcmQgYW5kIGN1c3RvbSBSZXF1ZXN0T3B0aW9uc1xuICAgICAgICBiYXNlUmVxdWVzdE9wdGlvbnMgPSBiYXNlUmVxdWVzdE9wdGlvbnMubWVyZ2Uob3B0aW9ucyk7XG5cbiAgICAgICAgbGV0IHJlc3BvbnNlID0gdGhpcy5odHRwLnJlcXVlc3QobmV3IFJlcXVlc3QoYmFzZVJlcXVlc3RPcHRpb25zKSkucGlwZShzaGFyZSgpKTtcbiAgICAgICAgdGhpcy5oYW5kbGVSZXNwb25zZShyZXNwb25zZSk7XG5cbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgIH1cblxuICAgIHByaXZhdGUgbWVyZ2VSZXF1ZXN0T3B0aW9uc0FyZ3Mob3B0aW9uczogUmVxdWVzdE9wdGlvbnNBcmdzLCBhZGRPcHRpb25zPzogUmVxdWVzdE9wdGlvbnNBcmdzKTogUmVxdWVzdE9wdGlvbnNBcmdzIHtcblxuICAgICAgICBsZXQgcmV0dXJuT3B0aW9uczogUmVxdWVzdE9wdGlvbnNBcmdzID0gb3B0aW9ucztcblxuICAgICAgICBpZiAob3B0aW9ucylcbiAgICAgICAgICAgICg8YW55Pk9iamVjdCkuYXNzaWduKHJldHVybk9wdGlvbnMsIGFkZE9wdGlvbnMpO1xuXG4gICAgICAgIHJldHVybiByZXR1cm5PcHRpb25zO1xuICAgIH1cblxuICAgIC8vIENoZWNrIGlmIHJlc3BvbnNlIGlzIGNvbXBsZXRlIGFuZCBuZXdlciwgdGhlbiB1cGRhdGUgc3RvcmFnZVxuICAgIHByaXZhdGUgaGFuZGxlUmVzcG9uc2UocmVzcG9uc2U6IE9ic2VydmFibGU8UmVzcG9uc2U+KTogdm9pZCB7XG4gICAgICAgIHJlc3BvbnNlLnN1YnNjcmliZShyZXMgPT4ge1xuICAgICAgICAgICAgdGhpcy5nZXRBdXRoSGVhZGVyc0Zyb21SZXNwb25zZSg8YW55PnJlcyk7XG4gICAgICAgIH0sIGVycm9yID0+IHtcbiAgICAgICAgICAgIHRoaXMuZ2V0QXV0aEhlYWRlcnNGcm9tUmVzcG9uc2UoPGFueT5lcnJvcik7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqXG4gICAgICogR2V0IEF1dGggRGF0YVxuICAgICAqXG4gICAgICovXG5cbiAgICAvLyBUcnkgdG8gbG9hZCBhdXRoIGRhdGFcbiAgICBwcml2YXRlIHRyeUxvYWRBdXRoRGF0YSgpOiB2b2lkIHtcblxuICAgICAgICBsZXQgdXNlclR5cGUgPSB0aGlzLmdldFVzZXJUeXBlQnlOYW1lKGdldFN0cmluZygndXNlclR5cGUnKSk7XG5cbiAgICAgICAgaWYgKHVzZXJUeXBlKVxuICAgICAgICAgICAgdGhpcy5hdEN1cnJlbnRVc2VyVHlwZSA9IHVzZXJUeXBlO1xuXG4gICAgICAgIHRoaXMuZ2V0QXV0aERhdGFGcm9tU3RvcmFnZSgpO1xuXG4gICAgICAgIGlmKHRoaXMuYWN0aXZhdGVkUm91dGUpXG4gICAgICAgICAgICB0aGlzLmdldEF1dGhEYXRhRnJvbVBhcmFtcygpO1xuXG4gICAgICAgIGlmICh0aGlzLmF0Q3VycmVudEF1dGhEYXRhKVxuICAgICAgICAgICAgdGhpcy52YWxpZGF0ZVRva2VuKCk7XG4gICAgfVxuXG4gICAgLy8gUGFyc2UgQXV0aCBkYXRhIGZyb20gcmVzcG9uc2VcbiAgICBwcml2YXRlIGdldEF1dGhIZWFkZXJzRnJvbVJlc3BvbnNlKGRhdGE6IGFueSk6IHZvaWQge1xuICAgICAgICBsZXQgaGVhZGVycyA9IGRhdGEuaGVhZGVycztcblxuICAgICAgICBsZXQgYXV0aERhdGE6IEF1dGhEYXRhID0ge1xuICAgICAgICAgICAgYWNjZXNzVG9rZW46ICAgIGhlYWRlcnMuZ2V0KCdhY2Nlc3MtdG9rZW4nKSxcbiAgICAgICAgICAgIGNsaWVudDogICAgICAgICBoZWFkZXJzLmdldCgnY2xpZW50JyksXG4gICAgICAgICAgICBleHBpcnk6ICAgICAgICAgaGVhZGVycy5nZXQoJ2V4cGlyeScpLFxuICAgICAgICAgICAgdG9rZW5UeXBlOiAgICAgIGhlYWRlcnMuZ2V0KCd0b2tlbi10eXBlJyksXG4gICAgICAgICAgICB1aWQ6ICAgICAgICAgICAgaGVhZGVycy5nZXQoJ3VpZCcpXG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5zZXRBdXRoRGF0YShhdXRoRGF0YSk7XG4gICAgfVxuXG4gICAgLy8gUGFyc2UgQXV0aCBkYXRhIGZyb20gcG9zdCBtZXNzYWdlXG4gICAgcHJpdmF0ZSBnZXRBdXRoRGF0YUZyb21Qb3N0TWVzc2FnZShkYXRhOiBhbnkpOiB2b2lkIHtcbiAgICAgICAgbGV0IGF1dGhEYXRhOiBBdXRoRGF0YSA9IHtcbiAgICAgICAgICAgIGFjY2Vzc1Rva2VuOiAgICBkYXRhWydhdXRoX3Rva2VuJ10sXG4gICAgICAgICAgICBjbGllbnQ6ICAgICAgICAgZGF0YVsnY2xpZW50X2lkJ10sXG4gICAgICAgICAgICBleHBpcnk6ICAgICAgICAgZGF0YVsnZXhwaXJ5J10sXG4gICAgICAgICAgICB0b2tlblR5cGU6ICAgICAgJ0JlYXJlcicsXG4gICAgICAgICAgICB1aWQ6ICAgICAgICAgICAgZGF0YVsndWlkJ11cbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLnNldEF1dGhEYXRhKGF1dGhEYXRhKTtcbiAgICB9XG5cbiAgICAvLyBUcnkgdG8gZ2V0IGF1dGggZGF0YSBmcm9tIHN0b3JhZ2UuXG4gICAgcHJpdmF0ZSBnZXRBdXRoRGF0YUZyb21TdG9yYWdlKCk6IHZvaWQge1xuXG4gICAgICAgIGxldCBhdXRoRGF0YTogQXV0aERhdGEgPSB7XG4gICAgICAgICAgICBhY2Nlc3NUb2tlbjogICAgZ2V0U3RyaW5nKCdhY2Nlc3NUb2tlbicpLFxuICAgICAgICAgICAgY2xpZW50OiAgICAgICAgIGdldFN0cmluZygnY2xpZW50JyksXG4gICAgICAgICAgICBleHBpcnk6ICAgICAgICAgZ2V0U3RyaW5nKCdleHBpcnknKSxcbiAgICAgICAgICAgIHRva2VuVHlwZTogICAgICBnZXRTdHJpbmcoJ3Rva2VuVHlwZScpLFxuICAgICAgICAgICAgdWlkOiAgICAgICAgICAgIGdldFN0cmluZygndWlkJylcbiAgICAgICAgfTtcblxuICAgICAgICBpZiAodGhpcy5jaGVja0F1dGhEYXRhKGF1dGhEYXRhKSlcbiAgICAgICAgICAgIHRoaXMuYXRDdXJyZW50QXV0aERhdGEgPSBhdXRoRGF0YTtcbiAgICB9XG5cbiAgICAvLyBUcnkgdG8gZ2V0IGF1dGggZGF0YSBmcm9tIHVybCBwYXJhbWV0ZXJzLlxuICAgIHByaXZhdGUgZ2V0QXV0aERhdGFGcm9tUGFyYW1zKCk6IHZvaWQge1xuICAgICAgICBpZih0aGlzLmFjdGl2YXRlZFJvdXRlLnF1ZXJ5UGFyYW1zKSAvLyBGaXggZm9yIFRlc3RpbmcsIG5lZWRzIHRvIGJlIHJlbW92ZWQgbGF0ZXJcbiAgICAgICAgICAgIHRoaXMuYWN0aXZhdGVkUm91dGUucXVlcnlQYXJhbXMuc3Vic2NyaWJlKHF1ZXJ5UGFyYW1zID0+IHtcbiAgICAgICAgICAgICAgICBsZXQgYXV0aERhdGE6IEF1dGhEYXRhID0ge1xuICAgICAgICAgICAgICAgICAgICBhY2Nlc3NUb2tlbjogICAgcXVlcnlQYXJhbXNbJ3Rva2VuJ10gfHwgcXVlcnlQYXJhbXNbJ2F1dGhfdG9rZW4nXSxcbiAgICAgICAgICAgICAgICAgICAgY2xpZW50OiAgICAgICAgIHF1ZXJ5UGFyYW1zWydjbGllbnRfaWQnXSxcbiAgICAgICAgICAgICAgICAgICAgZXhwaXJ5OiAgICAgICAgIHF1ZXJ5UGFyYW1zWydleHBpcnknXSxcbiAgICAgICAgICAgICAgICAgICAgdG9rZW5UeXBlOiAgICAgICdCZWFyZXInLFxuICAgICAgICAgICAgICAgICAgICB1aWQ6ICAgICAgICAgICAgcXVlcnlQYXJhbXNbJ3VpZCddXG4gICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgIGlmICh0aGlzLmNoZWNrQXV0aERhdGEoYXV0aERhdGEpKVxuICAgICAgICAgICAgICAgICAgICB0aGlzLmF0Q3VycmVudEF1dGhEYXRhID0gYXV0aERhdGE7XG4gICAgICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKlxuICAgICAqIFNldCBBdXRoIERhdGFcbiAgICAgKlxuICAgICAqL1xuXG4gICAgLy8gV3JpdGUgYXV0aCBkYXRhIHRvIHN0b3JhZ2VcbiAgICBwcml2YXRlIHNldEF1dGhEYXRhKGF1dGhEYXRhOiBBdXRoRGF0YSk6IHZvaWQge1xuXG4gICAgICAgIGlmICh0aGlzLmNoZWNrQXV0aERhdGEoYXV0aERhdGEpKSB7XG5cbiAgICAgICAgICAgIHRoaXMuYXRDdXJyZW50QXV0aERhdGEgPSBhdXRoRGF0YTtcblxuICAgICAgICAgICAgc2V0U3RyaW5nKCdhY2Nlc3NUb2tlbicsIGF1dGhEYXRhLmFjY2Vzc1Rva2VuKTtcbiAgICAgICAgICAgIHNldFN0cmluZygnY2xpZW50JywgYXV0aERhdGEuY2xpZW50KTtcbiAgICAgICAgICAgIHNldFN0cmluZygnZXhwaXJ5JywgYXV0aERhdGEuZXhwaXJ5KTtcbiAgICAgICAgICAgIHNldFN0cmluZygndG9rZW5UeXBlJywgYXV0aERhdGEudG9rZW5UeXBlKTtcbiAgICAgICAgICAgIHNldFN0cmluZygndWlkJywgYXV0aERhdGEudWlkKTtcblxuICAgICAgICAgICAgaWYgKHRoaXMuYXRDdXJyZW50VXNlclR5cGUgIT0gbnVsbClcbiAgICAgICAgICAgICAgICBzZXRTdHJpbmcoJ3VzZXJUeXBlJywgdGhpcy5hdEN1cnJlbnRVc2VyVHlwZS5uYW1lKTtcblxuICAgICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICpcbiAgICAgKiBWYWxpZGF0ZSBBdXRoIERhdGFcbiAgICAgKlxuICAgICAqL1xuXG4gICAgLy8gQ2hlY2sgaWYgYXV0aCBkYXRhIGNvbXBsZXRlIGFuZCBpZiByZXNwb25zZSB0b2tlbiBpcyBuZXdlclxuICAgIHByaXZhdGUgY2hlY2tBdXRoRGF0YShhdXRoRGF0YTogQXV0aERhdGEpOiBib29sZWFuIHtcblxuICAgICAgICBpZiAoXG4gICAgICAgICAgICBhdXRoRGF0YS5hY2Nlc3NUb2tlbiAhPSBudWxsICYmXG4gICAgICAgICAgICBhdXRoRGF0YS5jbGllbnQgIT0gbnVsbCAmJlxuICAgICAgICAgICAgYXV0aERhdGEuZXhwaXJ5ICE9IG51bGwgJiZcbiAgICAgICAgICAgIGF1dGhEYXRhLnRva2VuVHlwZSAhPSBudWxsICYmXG4gICAgICAgICAgICBhdXRoRGF0YS51aWQgIT0gbnVsbFxuICAgICAgICApIHtcbiAgICAgICAgICAgIGlmICh0aGlzLmF0Q3VycmVudEF1dGhEYXRhICE9IG51bGwpXG4gICAgICAgICAgICAgICAgcmV0dXJuIGF1dGhEYXRhLmV4cGlyeSA+PSB0aGlzLmF0Q3VycmVudEF1dGhEYXRhLmV4cGlyeTtcbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqXG4gICAgICogQ29uc3RydWN0IFBhdGhzIC8gVXJsc1xuICAgICAqXG4gICAgICovXG5cbiAgICBwcml2YXRlIGdldFVzZXJQYXRoKCk6IHN0cmluZyB7XG4gICAgICAgIGlmICh0aGlzLmF0Q3VycmVudFVzZXJUeXBlID09IG51bGwpXG4gICAgICAgICAgICByZXR1cm4gJyc7XG4gICAgICAgIGVsc2VcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmF0Q3VycmVudFVzZXJUeXBlLnBhdGggKyAnLyc7XG4gICAgfVxuXG4gICAgcHJpdmF0ZSBnZXRBcGlQYXRoKCk6IHN0cmluZyB7XG4gICAgICAgIGxldCBjb25zdHJ1Y3RlZFBhdGggPSAnJztcblxuICAgICAgICBpZiAodGhpcy5hdE9wdGlvbnMuYXBpQmFzZSAhPSBudWxsKVxuICAgICAgICAgICAgY29uc3RydWN0ZWRQYXRoICs9IHRoaXMuYXRPcHRpb25zLmFwaUJhc2UgKyAnLyc7XG5cbiAgICAgICAgaWYgKHRoaXMuYXRPcHRpb25zLmFwaVBhdGggIT0gbnVsbClcbiAgICAgICAgICAgIGNvbnN0cnVjdGVkUGF0aCArPSB0aGlzLmF0T3B0aW9ucy5hcGlQYXRoICsgJy8nO1xuXG4gICAgICAgIHJldHVybiBjb25zdHJ1Y3RlZFBhdGg7XG4gICAgfVxuXG4gICAgcHJpdmF0ZSBnZXRPQXV0aFBhdGgob0F1dGhUeXBlOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgICAgICBsZXQgb0F1dGhQYXRoOiBzdHJpbmc7XG5cbiAgICAgICAgb0F1dGhQYXRoID0gdGhpcy5hdE9wdGlvbnMub0F1dGhQYXRoc1tvQXV0aFR5cGVdO1xuXG4gICAgICAgIGlmIChvQXV0aFBhdGggPT0gbnVsbClcbiAgICAgICAgICAgIG9BdXRoUGF0aCA9IGAvYXV0aC8ke29BdXRoVHlwZX1gO1xuXG4gICAgICAgIHJldHVybiBvQXV0aFBhdGg7XG4gICAgfVxuXG4gICAgcHJpdmF0ZSBnZXRPQXV0aFVybChvQXV0aFBhdGg6IHN0cmluZywgY2FsbGJhY2tVcmw6IHN0cmluZywgd2luZG93VHlwZTogc3RyaW5nKTogc3RyaW5nIHtcbiAgICAgICAgbGV0IHVybDogc3RyaW5nO1xuXG4gICAgICAgIHVybCA9ICAgYCR7dGhpcy5hdE9wdGlvbnMub0F1dGhCYXNlfS8ke29BdXRoUGF0aH1gO1xuICAgICAgICB1cmwgKz0gIGA/b21uaWF1dGhfd2luZG93X3R5cGU9JHt3aW5kb3dUeXBlfWA7XG4gICAgICAgIHVybCArPSAgYCZhdXRoX29yaWdpbl91cmw9JHtlbmNvZGVVUklDb21wb25lbnQoY2FsbGJhY2tVcmwpfWA7XG5cbiAgICAgICAgaWYgKHRoaXMuYXRDdXJyZW50VXNlclR5cGUgIT0gbnVsbClcbiAgICAgICAgICAgIHVybCArPSBgJnJlc291cmNlX2NsYXNzPSR7dGhpcy5hdEN1cnJlbnRVc2VyVHlwZS5uYW1lfWA7XG5cbiAgICAgICAgcmV0dXJuIHVybDtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKlxuICAgICAqIE9BdXRoXG4gICAgICpcbiAgICAgKi9cblxuICAgIHByaXZhdGUgcmVxdWVzdENyZWRlbnRpYWxzVmlhUG9zdE1lc3NhZ2UoYXV0aFdpbmRvdzogYW55KTogT2JzZXJ2YWJsZTxhbnk+IHtcbiAgICAgICAgbGV0IHBvbGxlck9ic2VydiA9IGludGVydmFsKDUwMCk7XG5cbiAgICAgICAgbGV0IHJlc3BvbnNlT2JzZXJ2ID0gZnJvbUV2ZW50KHdpbmRvdywgJ21lc3NhZ2UnKS5waXBlKFxuICAgICAgICAgICAgcGx1Y2soJ2RhdGEnKSxcbiAgICAgICAgICAgIGZpbHRlcih0aGlzLm9BdXRoV2luZG93UmVzcG9uc2VGaWx0ZXIpXG4gICAgICAgICk7XG5cbiAgICAgICAgbGV0IHJlc3BvbnNlU3Vic2NyaXB0aW9uID0gcmVzcG9uc2VPYnNlcnYuc3Vic2NyaWJlKFxuICAgICAgICAgICAgdGhpcy5nZXRBdXRoRGF0YUZyb21Qb3N0TWVzc2FnZS5iaW5kKHRoaXMpXG4gICAgICAgICk7XG5cbiAgICAgICAgbGV0IHBvbGxlclN1YnNjcmlwdGlvbiA9IHBvbGxlck9ic2Vydi5zdWJzY3JpYmUoKCkgPT4ge1xuICAgICAgICAgICAgaWYgKGF1dGhXaW5kb3cuY2xvc2VkKVxuICAgICAgICAgICAgICAgIHBvbGxlclN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xuICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIGF1dGhXaW5kb3cucG9zdE1lc3NhZ2UoJ3JlcXVlc3RDcmVkZW50aWFscycsICcqJyk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIHJldHVybiByZXNwb25zZU9ic2VydjtcbiAgICB9XG5cbiAgICBwcml2YXRlIG9BdXRoV2luZG93UmVzcG9uc2VGaWx0ZXIoZGF0YTogYW55KTogYW55IHtcbiAgICAgICAgaWYoZGF0YS5tZXNzYWdlID09ICdkZWxpdmVyQ3JlZGVudGlhbHMnIHx8IGRhdGEubWVzc2FnZSA9PSAnYXV0aEZhaWx1cmUnKVxuICAgICAgICAgICAgcmV0dXJuIGRhdGE7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICpcbiAgICAgKiBVdGlsaXRpZXNcbiAgICAgKlxuICAgICAqL1xuXG4gICAgLy8gTWF0Y2ggdXNlciBjb25maWcgYnkgdXNlciBjb25maWcgbmFtZVxuICAgIHByaXZhdGUgZ2V0VXNlclR5cGVCeU5hbWUobmFtZTogc3RyaW5nKTogVXNlclR5cGUge1xuICAgICAgICBpZiAobmFtZSA9PSBudWxsIHx8IHRoaXMuYXRPcHRpb25zLnVzZXJUeXBlcyA9PSBudWxsKVxuICAgICAgICAgICAgcmV0dXJuIG51bGw7XG5cbiAgICAgICAgcmV0dXJuIHRoaXMuYXRPcHRpb25zLnVzZXJUeXBlcy5maW5kKFxuICAgICAgICAgICAgdXNlclR5cGUgPT4gdXNlclR5cGUubmFtZSA9PT0gbmFtZVxuICAgICAgICApO1xuICAgIH1cbn0iXX0=