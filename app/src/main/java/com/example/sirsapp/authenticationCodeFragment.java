package com.example.sirsapp;

import android.os.Bundle;

import androidx.fragment.app.Fragment;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

public class authenticationCodeFragment extends Fragment {
    public authenticationCodeFragment() {
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View root = inflater.inflate(R.layout.fragment_authentication_code, container, false);

        getActivity().setTitle("Authentication Code");

        return root;
    }
}