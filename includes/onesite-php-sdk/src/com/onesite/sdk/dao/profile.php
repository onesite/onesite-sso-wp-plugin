<?php
/**
 * Copyright 2012 ONESite, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
/**
 * DAO for an profile object from ONEsite.
 *
 * @author  Mike Benshoof <mbenshoof@onesite.com>
 */
class onesite_sdk_dao_profile extends onesite_sdk_dao
{
	/**
	 * Define the public properties here.
	 *
	 * @return void
	 */
	protected function init()
	{
		// The public field mapping to the local properties.
		$this->_public_fields = array(
			'firstName'    => 'first_name',
			'lastName'     => 'last_name',
			'address'      => 'loc_custom',
			'city'         => 'loc_city',
			'state'        => 'loc_state',
			'zip'          => 'loc_zip',
			'country'      => 'loc_country',
			'gender'       => 'gender',
			'referringUrl' => 'referring_url',
		);
	}
}

         