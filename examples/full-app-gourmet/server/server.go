package server

import (
	"context"
	"net/http"

	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"

	"github.com/rs/cors"

	"github.com/go-fuego/fuego"
	"github.com/go-fuego/fuego/examples/full-app-gourmet/handler"
	"github.com/go-fuego/fuego/examples/full-app-gourmet/static"
	"github.com/go-fuego/fuego/examples/full-app-gourmet/templates"
	"github.com/go-fuego/fuego/option"
)

type Resources struct {
	HandlersResources handler.Resource
	CorsOrigins       []string
}

func cache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")

		h.ServeHTTP(w, r)
	})
}

func (rs Resources) Setup(
	options ...func(*fuego.Server),
) *fuego.Server {
	serverOptions := []func(*fuego.Server){
		fuego.WithTemplateFS(templates.FS),
		fuego.WithTemplateGlobs("**/*.html", "**/**/*.html"),
		fuego.WithGlobalMiddlewares(cors.New(cors.Options{
			AllowedOrigins: rs.CorsOrigins,
			AllowedHeaders: []string{"*"},
			MaxAge:         300,
		}).Handler),
		fuego.WithRouteOptions(
			fuego.OptionAddResponse(http.StatusForbidden, "Forbidden", fuego.Response{Type: fuego.HTTPError{}}),
		),
		fuego.WithEngineOptions(
			fuego.WithErrorHandler(customErrorHandler),
		),
	}

	options = append(serverOptions, options...)

	// Create server with some options
	app := fuego.NewServer(options...)

	app.OpenAPI.Description().Info.Title = "Gourmet API"

	// Register middlewares (functions that will be executed before AND after the controllers, in the order they are registered)
	// With fuego, you can use any existing middleware that relies on `net/http`, or create your own
	fuego.Use(app, chiMiddleware.Compress(5, "text/html", "text/css", "application/json"))

	fuego.Handle(app, "/static/", http.StripPrefix("/static", static.Handler()), option.Middleware(cache))

	fuego.Use(app,
		TokenToContext(rs.HandlersResources.Security, fuego.TokenFromCookie, fuego.TokenFromHeader),
	)
	// Register views (controllers that return HTML pages)
	rs.HandlersResources.Routes(app)

	return app
}

func TokenToContext(security fuego.Security, searchFunc ...func(*http.Request) string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the authorizationHeader from the header
			token := ""
			for _, f := range searchFunc {
				token = f(r)
				if token != "" {
					break
				}
			}

			if token == "" {
				// Unauthenticated, might be legit
				next.ServeHTTP(w, r)
				return
			}

			// Validate the token
			t, err := security.ValidateToken(token)
			if err != nil {
				fuego.SendJSONError(w, nil, err)
				return
			}

			// Get the claims
			claims := t.Claims.(jwt.MapClaims)

			// Set the subject and roles in the context
			ctx := r.Context()
			ctx = context.WithValue(ctx, "JWT", claims)
			r = r.WithContext(ctx)

			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}
