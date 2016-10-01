<?php
//
// Description
// -----------
// This function will check if the user has access to the landingpages module.
//
// Arguments
// ---------
// q:
// station_id:                  The ID of the station to check the session user against.
// method:                      The requested method.
//
// Returns
// -------
// <rsp stat='ok' />
//
function qruqsp_bugs_checkAccess(&$q, $business_id, $method) {
    //
    // Check if the business is active and the module is enabled
    //
    qruqsp_core_loadMethod($q, 'qruqsp', 'businesses', 'private', 'checkModuleAccess');
    $rc = qruqsp_core_checkModuleAccess($q, $business_id, 'qruqsp', 'bugs');
    if( $rc['stat'] != 'ok' ) {
        return $rc;
    }

    if( !isset($rc['ruleset']) ) {
        return array('stat'=>'fail', 'err'=>array('code'=>'qruqsp.bugs.1000', 'msg'=>'No permissions granted'));
    }

    //
    // Sysadmins are allowed full access
    //
    if( ($q['session']['user']['perms'] & 0x01) == 0x01 ) {
        return array('stat'=>'ok');
    }

    //
    // Check to makes sure the session user is a station operator
    //
    $strsql = "SELECT business_id, user_id "
        . "FROM qruqsp_business_users "
        . "WHERE business_id = '" . qruqsp_core_dbQuote($q, $business_id) . "' "
        . "AND user_id = '" . qruqsp_core_dbQuote($q, $q['session']['user']['id']) . "' "
        . "AND package = 'qruqsp' "
        . "AND status = 10 "
        . "AND permission_group = 'operators' "
        . "";
    qruqsp_core_loadMethod($q, 'qruqsp', 'core', 'private', 'dbHashQuery');
    $rc = qruqsp_core_dbHashQuery($q, $strsql, 'qruqsp.businesses', 'user');
    if( $rc['stat'] != 'ok' ) {
        return array('stat'=>'fail', 'err'=>array('code'=>'qruqsp.bugs.1001', 'msg'=>'Access denied.'));
    }
    //
    // If the user has permission, return ok
    //
    if( isset($rc['rows']) && isset($rc['rows'][0])
        && $rc['rows'][0]['user_id'] > 0 && $rc['rows'][0]['user_id'] == $q['session']['user']['id'] ) {
        return array('stat'=>'ok');
    }

    //
    // By default fail
    //
    return array('stat'=>'fail', 'err'=>array('code'=>'qruqsp.bugs.1002', 'msg'=>'Access denied'));
}
?>
