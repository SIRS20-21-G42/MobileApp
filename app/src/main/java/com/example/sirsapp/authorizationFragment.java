package com.example.sirsapp;

import android.os.Bundle;

import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import com.example.sirsapp.ui.Authorization.AuthorizationAdapter;
import com.example.sirsapp.ui.Authorization.AuthorizationDialog;
import com.example.sirsapp.ui.Authorization.AuthorizationItem;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A simple {@link Fragment} subclass.
 */
public class authorizationFragment extends Fragment {

    private RecyclerView recyclerView;
    private RecyclerView.LayoutManager layoutManager;
    public static List<AuthorizationItem> list = new ArrayList<>();
    public static final Object lock = new Object();
    private AuthorizationAdapter recyclerAdapter;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment

        View view = inflater.inflate(R.layout.fragment_authorization, container, false);

        // setting up the recycler view with layout manager
        this.recyclerView = view.findViewById(R.id.authorizationRecyclerView);
        this.recyclerView.setHasFixedSize(true);
        this.layoutManager = new LinearLayoutManager(getActivity());
        this.recyclerView.setLayoutManager(this.layoutManager);

        // sending the list to the adapter
        this.recyclerAdapter = new AuthorizationAdapter(getActivity(), list);
        this.recyclerView.setAdapter(this.recyclerAdapter);


        //setting up the interface clickables
        setupOnClickButtons();

        return view;
    }

    private void setupOnClickButtons() {
        // setting up the buttons for the interface
        this.recyclerAdapter.setOnItemClickListener(new AuthorizationAdapter.OnItemClickListener() {
            @Override
            public void onItemClick(int position) {
                showPosition(position);
            }

            @Override
            public void onItemAccept(int position) {
                acceptButtonPressed(position);
            }

            @Override
            public void onItemDeny(int position) {
                declineButtonPressed(position);
            }
        });
    }

    private void showPosition(int position){
        // shows the hash for a position
        AuthorizationItem item = list.get(position);
        AuthorizationDialog dialog = new AuthorizationDialog(position, "Confirmation ID", item.getHash() + "\n" + item.getDate());
        dialog.show(getParentFragmentManager(), "item dialog");
    }

    private void acceptButtonPressed(int position){
        // show confirmation dialog for acceptance of item
        AuthorizationItem item = list.get(position);
        String text = "Are you sure you want to ACCEPT the item:\n" + item.getHash() + "\n" + item.getDate();
        AuthorizationDialog dialog = new AuthorizationDialog(position, "Confirmation", text, AuthorizationDialog.ACCEPT, new AuthorizationDialog.DialogConfirmation() {
            @Override
            public void onAccept(int position) {
                acceptAuthorization(position);
            }
        });
        dialog.show(getParentFragmentManager(), "item dialog");
    }

    private void declineButtonPressed(int position){
        // show confirmation dialog for decline of item
        AuthorizationItem item = list.get(position);
        String text = "Are you sure you want to DECLINE the item:\n" + item.getHash() + "\n" + item.getDate();
        AuthorizationDialog dialog = new AuthorizationDialog(position, "Confirmation", text, AuthorizationDialog.DECLINE, new AuthorizationDialog.DialogConfirmation() {
            @Override
            public void onAccept(int position) {
                declineAuthorization(position);
            }
        });
        dialog.show(getParentFragmentManager(), "item dialog");
    }

    public void acceptAuthorization(int position) {
        // accept authorization confirmed
        synchronized (lock) {
            AuthorizationItem item = list.get(position);
            ((DrawerActivity) getActivity()).answerAuthRequest(item.getHash(), true);
            recyclerAdapter.notifyItemRemoved(position);
        }
    }

    public void declineAuthorization(int position) {
        // decline authorization confirmed
        synchronized (lock) {
            AuthorizationItem item = list.get(position);
            ((DrawerActivity) getActivity()).answerAuthRequest(item.getHash(), false);
            recyclerAdapter.notifyItemRemoved(position);
        }
    }
}