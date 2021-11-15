import { CredentialManagerScreen } from '../screens/CredentialManagerScreen';
import { StackNavigatorParams } from '../types';
import { EnterPasscodeScreen } from '../screens/EnterPasscodeScreen';
import { AddWorkspaceScreen } from '../screens/AddWorkspaceScreen';
import { SetPasscodeScreen } from '../screens/SetPasscodeScreen';
import { EntryScreen } from '../screens/EntryScreen';
import { HomeScreen } from '../screens/HomeScreen';
import * as React from 'react';
import {
  StackNavigationOptions,
  createStackNavigator,
} from '@react-navigation/stack';

const options: StackNavigationOptions = {
  headerShown: false,
};
const { Navigator, Screen } = createStackNavigator<StackNavigatorParams>();

export const StackNavigator = (): JSX.Element => (
  <Navigator initialRouteName="EntryScreen" screenOptions={options}>
    <Screen
      component={CredentialManagerScreen}
      name="CredentialManagerScreen"
    />
    <Screen component={EnterPasscodeScreen} name="EnterPasscodeScreen" />
    <Screen component={AddWorkspaceScreen} name="AddWorkspaceScreen" />
    <Screen component={SetPasscodeScreen} name="SetPasscodeScreen" />
    <Screen component={EntryScreen} name="EntryScreen" />
    <Screen component={HomeScreen} name="HomeScreen" />
  </Navigator>
);
