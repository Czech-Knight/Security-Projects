FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY src/ConstructTrack.Web/ConstructTrack.Web.csproj src/ConstructTrack.Web/
RUN dotnet restore src/ConstructTrack.Web/ConstructTrack.Web.csproj

COPY . .
RUN dotnet publish src/ConstructTrack.Web/ConstructTrack.Web.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "ConstructTrack.Web.dll"]
