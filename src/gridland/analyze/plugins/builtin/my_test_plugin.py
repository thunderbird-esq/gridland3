from gridland.analyze.plugins.manager import AnalysisPlugin, PluginMetadata

class MyTestPlugin(AnalysisPlugin):
    metadata = PluginMetadata(
        name="My Test Plugin",
        version="1.0.0",
        author="Test",
        description="A simple test plugin.",
        plugin_type="custom",
        supported_services=[],
        supported_ports=[],
    )

    async def analyze(self, target_ip: str, target_port: int, service: str = "", banner: str = ""):
        return []
