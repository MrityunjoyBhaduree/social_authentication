from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse
from django.conf import settings
from django.conf.urls.static import static

# For swagger documentation
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="Implement Social Authentication",
        default_version="v1",
        description="API For View The Social Authentication"
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)


def home_view(request):
    html = (
        "<html>"
        "<body>"
        "<h1>Wellcome To Social Authentication Application.</h1>"
        "<a href='http://127.0.0.1:8000/swagger/'>Social Authentication API View</a>"
        "</body>"
        "</html"
    )
    return HttpResponse(html)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home_view, name='home'),
    path('api/v1/social/', include('social.urls')),
    path('api/v1/token/refresh/', TokenRefreshView.as_view(),
         name="token_refresh"),  # to get new tokens
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0),
         name='schema_swagger_ui')
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
