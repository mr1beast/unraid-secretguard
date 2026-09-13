<?php
require_once '/usr/local/emhttp/plugins/unraid-secretguard/include/SecretGuard.php';
$settings=SecretGuard::settings();
@mkdir('/run/unraid-secretguard',0700,true);

// Vault safety runs regardless of template-notification settings.
// After reboot the runtime key is gone; any Vault-protected container that
// autostarts is stopped and remembered so Unlock can recreate/start it.
if(($settings['STORAGE_MODE']??'plain')==='vault' && is_file(SecretGuard::VAULT_META_FILE) && !is_file(SecretGuard::MASTER_KEY_FILE)) {
    try { SecretGuard::enforceLockedVault($settings['SECRET_DIR']); } catch(Throwable $e) {
        @exec('/usr/bin/logger -t unraid-secretguard '.escapeshellarg('Vault boot-lock enforcement failed: '.$e->getMessage()).' >/dev/null 2>&1');
    }
}

if(($settings['AUTO_WATCH']??'yes')!=='yes') exit(0);
$stateFile='/run/unraid-secretguard/watch-state.json';
$old=is_file($stateFile)?json_decode((string)file_get_contents($stateFile),true):[]; if(!is_array($old))$old=[];
$new=[];
$installed=SecretGuard::installedContainerNames();
if(!$installed){ @file_put_contents($stateFile,json_encode($new),LOCK_EX); exit(0); }
foreach(glob(SecretGuard::TEMPLATE_DIR.'/*.xml')?:[] as $file){
 $container=SecretGuard::templateContainerName($file);
 if($container==='' || !isset($installed[$container])) continue;
 $hash=@hash_file('sha256',$file); if(!$hash)continue; $new[$file]=$hash;
 if(isset($old[$file])&&hash_equals((string)$old[$file],$hash))continue;
 $findings=array_filter(SecretGuard::scanFile($file),fn($r)=>$r['has_value']&&in_array($r['classification'],['high','medium'],true));
 if(!$findings)continue;
 $containers=array_values(array_unique(array_column($findings,'container')));$high=count(array_filter($findings,fn($r)=>$r['classification']==='high'));$med=count($findings)-$high;
 $desc='SecretGuard detected '.count($findings).' possible secret(s) in '.implode(', ',$containers).' ('.$high.' high, '.$med.' medium). Open Settings > User Utilities > Unraid SecretGuard to review them.';
 $notify='/usr/local/emhttp/webGui/scripts/notify';
 if(is_executable($notify))@exec(escapeshellcmd($notify).' -e '.escapeshellarg('Unraid SecretGuard').' -s '.escapeshellarg('Docker secrets detected').' -d '.escapeshellarg($desc).' -i warning >/dev/null 2>&1');
}
@file_put_contents($stateFile,json_encode($new),LOCK_EX);@chmod($stateFile,0600);
