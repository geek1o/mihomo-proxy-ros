from pathlib import Path
import yaml
app=yaml.safe_load(Path('apps/mihomo-proxy-ros.yaml').read_text())
catalog=yaml.safe_load(Path('apps/catalog.yaml').read_text())
assert catalog==[app]
assert app['page']=='https://github.com/geek1o/mihomo-proxy-ros'
assert app['supported-archs']==['arm64','x86']
service=app['services']['proxy']
assert service['image'].startswith('ghcr.io/geek1o/mihomo-proxy-ros:fork-')
assert not ({'privileged','cap_add','network_mode'} & set(service))
assert 'state:/data' in service['volumes']
assert service['environment']['MP_UI_PASSWORD_FILE']=='/run/secrets/ui_password'
assert service['secrets']==['ui_password']
assert 'MP_UI_PASSWORD' not in service['environment']
print('Apps manifest and catalog agree')
